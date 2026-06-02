// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/network_identity_interface.h"
#include "ccf/service/tables/service.h"
#include "node/historical_queries.h"
#include "node/identity.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "node/rpc/node_interface.h"
#include "service/internal_tables_access.h"

#include <atomic>
#include <chrono>
#include <mutex>

namespace ccf
{
  class NetworkIdentitySubsystem : public NetworkIdentitySubsystemInterface
  {
  protected:
    static constexpr std::chrono::milliseconds RETRY_INTERVAL{100};
    static constexpr int MAX_FETCH_ATTEMPTS = 30;

    AbstractNodeState& node_state;
    const std::unique_ptr<NetworkIdentity>& network_identity;
    std::shared_ptr<historical::StateCacheImpl> historical_cache;

    // chain_mutex guards every field below. fetch_status and fetch_active
    // are atomic so RPC threads can fast-path without taking the mutex,
    // but they must take the mutex before reading/writing any of the
    // fields below.
    mutable std::mutex chain_mutex;
    std::map<SeqNo, CoseEndorsement> endorsements;
    std::map<SeqNo, ccf::crypto::ECPublicKeyPtr> trusted_keys;
    std::optional<TxID> current_service_from;
    SeqNo earliest_endorsed_seq{0};
    bool has_predecessors{false};

    // Number of consecutive failed attempts to fetch the current pending
    // predecessor. Reset on every successful fetch and at the start of
    // every extension cycle. When it reaches MAX_FETCH_ATTEMPTS, the
    // current cycle ends without scheduling further attempts.
    int fetch_attempts{0};
    ccf::tasks::Task poll_task;

    std::atomic<FetchStatus> fetch_status{FetchStatus::Fetching};

    // True while a fetch cycle is active (bootstrap or caller-triggered
    // extension). Cleared when a cycle ends in Ready or PartialReady.
    // trigger_extension uses compare-and-exchange to ensure only one
    // extension cycle runs at a time; the bootstrap cycle that begins in
    // the constructor sets it to true. Delayed task bodies check
    // fetch_active at entry so stale callbacks from completed cycles
    // no-op cleanly.
    std::atomic<bool> fetch_active{true};

  public:
    NetworkIdentitySubsystem(
      AbstractNodeState& node_state_,
      const std::unique_ptr<NetworkIdentity>& network_identity_,
      std::shared_ptr<ccf::historical::StateCacheImpl> historical_cache_) :
      node_state(node_state_),
      network_identity(network_identity_),
      historical_cache(std::move(historical_cache_))
    {
      fetch_first();
    }

    ~NetworkIdentitySubsystem() override
    {
      // cancel_task only prevents the captured lambda from running on its next
      // scheduled dispatch; it does not synchronize with an in-flight
      // execution. Safety relies on the enclave joining task workers before
      // destroying the node context that owns this subsystem.
      std::lock_guard<std::mutex> g(chain_mutex);
      if (poll_task)
      {
        poll_task->cancel_task();
      }
    }

    [[nodiscard]] FetchStatus endorsements_fetching_status() const override
    {
      return fetch_status.load();
    }

    const std::unique_ptr<NetworkIdentity>& get() override
    {
      return network_identity;
    }

    void trigger_extension() override
    {
      // Fast-path: only PartialReady can be extended.
      if (fetch_status.load() != FetchStatus::PartialReady)
      {
        return;
      }

      // Claim the cycle. If another cycle is already active (bootstrap
      // racing in, or another concurrent trigger) this CAS fails and we
      // silently no-op.
      bool expected = false;
      if (!fetch_active.compare_exchange_strong(expected, true))
      {
        return;
      }

      SeqNo seq{};
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        if (endorsements.empty())
        {
          // PartialReady is only reached after at least one bootstrap
          // fetch has inserted the topmost endorsement; defensive.
          LOG_FAIL_FMT(
            "trigger_extension called in PartialReady but endorsements map "
            "is empty; ignoring");
          fetch_active.store(false);
          return;
        }
        const auto& earliest = endorsements.begin()->second;
        if (!earliest.previous_version.has_value())
        {
          // Earliest is a self-endorsement terminator; chain is complete
          // and should be Ready, not PartialReady. Defensive no-op.
          LOG_FAIL_FMT(
            "trigger_extension called in PartialReady but earliest "
            "endorsement is a self-endorsement; ignoring");
          fetch_active.store(false);
          return;
        }
        seq = *earliest.previous_version;
        fetch_attempts = 0;
      }

      // Status stays PartialReady; readers continue to see the existing
      // partial chain throughout the extension attempt. The cycle ends
      // by either transitioning to Ready (chain healed back to the
      // self-endorsement), staying in PartialReady (retries exhausted
      // again), or transitioning to Failed on a chain-integrity error.
      ccf::tasks::add_task(ccf::tasks::make_basic_task(
        [this, seq]() { this->fetch_next_at(seq); }));
    }

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const override
    {
      const auto status = fetch_status.load();
      if (status == FetchStatus::Fetching)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "COSE endorsements chain requested for seqno {} but identity "
          "history fetching is still in progress",
          seqno));
      }

      std::lock_guard<std::mutex> g(chain_mutex);

      if (!current_service_from.has_value())
      {
        LOG_FAIL_FMT(
          "Unset current_service_from when fetching endorsements chain");
        return std::nullopt;
      }

      if (!has_predecessors || seqno >= current_service_from->seqno)
      {
        return CoseEndorsementsChain{};
      }

      auto it = endorsements.upper_bound(seqno);
      if (it == endorsements.begin())
      {
        // seqno is below the earliest endorsement we have validated. In
        // Ready the chain has reached its self-endorsement terminator, so
        // this is a pre-history seqno that no chain will ever cover and
        // we return an empty chain. In PartialReady the chain is partial
        // and a caller-triggered extension may yet pull in earlier
        // endorsements; return std::nullopt so the caller can decide
        // whether to invoke trigger_extension and retry.
        if (status == FetchStatus::Ready)
        {
          LOG_INFO_FMT(
            "No endorsements for seqno {} (earliest endorsed is {}); chain "
            "is complete, treating as pre-history",
            seqno,
            earliest_endorsed_seq);
          return CoseEndorsementsChain{};
        }
        LOG_INFO_FMT(
          "No endorsements yet for seqno {} (earliest endorsed is {}); "
          "chain is partial",
          seqno,
          earliest_endorsed_seq);
        return std::nullopt;
      }

      CoseEndorsementsChain result;
      for (--it; it != endorsements.end(); ++it)
      {
        result.push_back(it->second.endorsement);
      }
      std::reverse(result.begin(), result.end());
      return result;
    }

    [[nodiscard]] ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const override
    {
      if (fetch_status.load() == FetchStatus::Fetching)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "Trusted key requested for seqno {} but identity history "
          "fetching is still in progress",
          seqno));
      }
      std::lock_guard<std::mutex> g(chain_mutex);
      if (trusted_keys.empty())
      {
        throw std::logic_error(fmt::format(
          "No trusted keys fetched when requested one for seqno {}", seqno));
      }
      auto it = trusted_keys.upper_bound(seqno);
      if (it == trusted_keys.begin())
      {
        // The earliest known trusted seqno is greater than the requested
        // one. In PartialReady the caller may invoke trigger_extension to
        // try to fetch earlier endorsements.
        return nullptr;
      }
      const auto& [key_seqno, key_ptr] = *(--it);
      if (key_seqno > seqno)
      {
        throw std::logic_error(fmt::format(
          "Resolved trusted key for {} with wrong starting seqno {}",
          seqno,
          key_seqno));
      }
      return key_ptr;
    }

    [[nodiscard]] TrustedKeys get_trusted_keys() const override
    {
      if (fetch_status.load() == FetchStatus::Fetching)
      {
        throw IdentityHistoryNotFetched(
          "Trusted keys requested but identity history fetching is still "
          "in progress");
      }
      std::lock_guard<std::mutex> g(chain_mutex);
      return trusted_keys;
    }

  private:
    void retry_first_fetch()
    {
      using namespace std::chrono_literals;
      static constexpr auto retry_after = 1s;
      ccf::tasks::add_delayed_task(
        ccf::tasks::make_basic_task([this]() { this->fetch_first(); }),
        retry_after);
    }

    void fail_fetching(const std::string& err = "")
    {
      if (!err.empty())
      {
        LOG_FAIL_FMT("Failed fetching network identity: {}", err);
      }
      fetch_status.store(FetchStatus::Failed);
      fetch_active.store(false);

      // The caller may want to re-capture this, but by default it's supposed
      // to fail the node startup early. This is purely reading, so there's
      // no risk of corruption, but the endorsement chain is essential for
      // the node to produce receipts for the past epochs, which is a
      // must-have functionality.
      throw std::runtime_error("Failed fetching network identity: " + err);
    }

    // End the active cycle in Ready. Called only when the chain has been
    // walked back to a self-endorsement (or trivially has no predecessors).
    // The bootstrap path may pass new_trusted_keys to install; the
    // extension path passes std::nullopt since process_extension has
    // already kept trusted_keys up to date incrementally.
    void complete_fetching_ready(
      std::optional<TrustedKeys> new_trusted_keys = std::nullopt)
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      if (new_trusted_keys.has_value())
      {
        trusted_keys = std::move(*new_trusted_keys);
      }
      poll_task.reset();
      fetch_attempts = 0;
      fetch_status.store(FetchStatus::Ready);
      fetch_active.store(false);
    }

    // Bootstrap-time transition Fetching → PartialReady. Validate whatever
    // partial chain we have and build trusted_keys. The front-end
    // connection to current_service_from is still required: if we don't
    // even have a front connection, the chain is fundamentally broken and
    // we fail-hard.
    void complete_bootstrap_partial()
    {
      if (!current_service_from.has_value())
      {
        fail_fetching(
          "Unset current_service_from when transitioning to PartialReady");
        return; // to silence clang-tidy unchecked optional
      }

      TrustedKeys new_trusted_keys;
      try
      {
        validate_chain_integrity_pairwise(endorsements);
        validate_chain_front_connection(endorsements, *current_service_from);
        new_trusted_keys = build_trusted_keys(
          endorsements,
          network_identity->get_key_pair()->public_key_der(),
          *current_service_from);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      {
        std::lock_guard<std::mutex> g(chain_mutex);
        trusted_keys = std::move(new_trusted_keys);
        poll_task.reset();
        fetch_status.store(FetchStatus::PartialReady);
        fetch_active.store(false);
      }
    }

    // End an extension cycle in PartialReady (retries exhausted). No
    // validation needed because process_extension validates incrementally
    // — the chain we hold has already been verified.
    void complete_extension_partial()
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      poll_task.reset();
      fetch_attempts = 0;
      // Status is already PartialReady; only the cycle flag flips.
      fetch_active.store(false);
    }

    void fetch_first()
    {
      if (!node_state.is_part_of_network())
      {
        LOG_INFO_FMT(
          "Retry fetching network identity as node is not part of the network "
          "yet");
        retry_first_fetch();
        return;
      }

      auto store = node_state.get_store();
      auto tx = store->create_read_only_tx();

      if (!current_service_from.has_value())
      {
        auto* service_info_handle =
          tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
        auto service_info = service_info_handle->get();
        if (
          !service_info ||
          !service_info->current_service_create_txid.has_value())
        {
          LOG_INFO_FMT(
            "Retrying fetching network identity as current service create txid "
            "is not yet available");
          retry_first_fetch();
          return;
        }

        if (service_info->status != ServiceStatus::OPEN)
        {
          // It can happen that node advances its internal state machine to
          // part-of-network, but the service opening tx has not been replicated
          // yet. This will cause the first fetched endorsement to be obsolete,
          // but waiting for ServiceStatus::OPEN is sufficient, as it's supposed
          // to arrive in the same TX that the previous identity endorsement.
          LOG_INFO_FMT(
            "Retrying fetching network identity as service is not yet open");
          retry_first_fetch();
          return;
        }

        current_service_from = service_info->current_service_create_txid;
      }

      auto* previous_identity_endorsement =
        tx.ro<ccf::PreviousServiceIdentityEndorsement>(
          ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);

      auto endorsement = previous_identity_endorsement->get();
      if (!endorsement.has_value())
      {
        LOG_INFO_FMT(
          "Retrying fetching network identity as there is no previous service "
          "identity endorsement yet");
        retry_first_fetch();
        return;
      }

      if (is_self_endorsement(endorsement.value()))
      {
        if (
          current_service_from->seqno !=
          endorsement->endorsement_epoch_begin.seqno)
        {
          fail_fetching(fmt::format(
            "The first fetched endorsement is a self-endorsement with seqno {} "
            "which is different from current_service_create_txid {}",
            endorsement->endorsement_epoch_begin.seqno,
            current_service_from->seqno));
        }

        LOG_INFO_FMT(
          "The very first service endorsement is self-signed at {}, no "
          "endorsement chain will be preloaded",
          current_service_from->seqno);

        has_predecessors = false;
        complete_bootstrap_ready();
        return;
      }

      has_predecessors = true;
      earliest_endorsed_seq = current_service_from->seqno;
      process_endorsement(endorsement.value());
    }

    // Bootstrap reached the self-endorsement (or had no predecessors).
    // Validate the accumulated chain, build trusted keys, and transition
    // to Ready.
    void complete_bootstrap_ready()
    {
      if (!current_service_from.has_value())
      {
        fail_fetching("Unset current_service_from when completing chain fetch");
        return; // to silence clang-tidy unchecked optional
      }

      TrustedKeys new_trusted_keys;
      try
      {
        validate_chain_integrity_pairwise(endorsements);
        validate_chain_front_connection(endorsements, *current_service_from);
        new_trusted_keys = build_trusted_keys(
          endorsements,
          network_identity->get_key_pair()->public_key_der(),
          *current_service_from);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      complete_fetching_ready(std::move(new_trusted_keys));
    }

    void process_endorsement(const ccf::CoseEndorsement& endorsement)
    {
      if (is_ill_formed(endorsement))
      {
        // For double-sealed cases, which could have happened in the past. We
        // mark with failed logs, but skip intentionally if there are other
        // endorsements that follow. The overall chain integrity will be
        // checked at the end and will fail anyway if it's not intact.
        if (endorsement.previous_version.has_value())
        {
          LOG_INFO_FMT(
            "Fetched endorsement for {} - {} is ill-formed but has a "
            "predecessor, so skipping this entry",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end));
          fetch_next_at(endorsement.previous_version.value());
          return;
        }
        fail_fetching(fmt::format(
          "Found an ill-formed endorsement for {} - {} which has no "
          "predecessor",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      // Fetching = bootstrap (no readers yet, defer validation to
      // completion). PartialReady = caller-triggered extension cycle
      // (readers may be active, validate incrementally and publish under
      // the mutex).
      if (fetch_status.load() == FetchStatus::Fetching)
      {
        process_initial(endorsement);
      }
      else
      {
        process_extension(endorsement);
      }
    }

    // Initial bootstrap path: status is still Fetching, no concurrent
    // readers. Accumulate into the endorsements map directly; defer chain
    // validation until the end (complete_bootstrap_ready).
    void process_initial(const ccf::CoseEndorsement& endorsement)
    {
      const auto from = endorsement.endorsement_epoch_begin.seqno;
      if (is_self_endorsement(endorsement))
      {
        if (endorsements.find(from) == endorsements.end())
        {
          fail_fetching(fmt::format(
            "Fetched self-endorsement with seqno {} which has not been seen",
            from));
        }
        LOG_INFO_FMT("Got self-endorsement at {}, stopping fetching", from);
        complete_bootstrap_ready();
        return;
      }

      if (from >= earliest_endorsed_seq)
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement with seqno {} which is greater than "
          "the earliest known in the chain {}",
          from,
          earliest_endorsed_seq));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        fail_fetching(
          fmt::format("Fetched endorsement at {} has no epoch end", from));
        return; // to silence clang-tidy unchecked optional
      }

      if (endorsements.find(from) != endorsements.end())
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement with seqno {} which already exists",
          from));
      }

      LOG_INFO_FMT(
        "Fetched service endorsement from {} to {}",
        from,
        endorsement.endorsement_epoch_end->seqno);

      // No concurrent readers during bootstrap, but maintain mutex
      // discipline so eventual transitions pair correctly with subsequent
      // extension writes.
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        earliest_endorsed_seq = from;
        endorsements.insert({from, endorsement});
      }

      if (!endorsement.previous_version.has_value())
      {
        fail_fetching(fmt::format(
          "Non-self-endorsement at seqno {} unexpectedly has no "
          "previous_version",
          from));
        return; // to silence clang-tidy unchecked optional
      }
      fetch_next_at(*endorsement.previous_version);
    }

    // Extension path: status is PartialReady (caller-triggered cycle). RPC
    // readers may be accessing the chain concurrently. Verify the new
    // (older) endorsement chains to the existing earliest entry, then
    // publish under the mutex. The existing chain was already validated
    // inductively at bootstrap (or by prior extensions), so only the
    // incremental link is checked. Genuine chain-integrity violations
    // fail-hard via fail_fetching → throw → task worker abort().
    //
    // Chain-link predicate (from build_trusted_keys, oldest→newest):
    //   for adjacent (older A, newer B): B.endorsed_key == A.endorsing_key
    //   for the newest entry N: N.endorsing_key == current_service_pkey
    // When extending backward with NEW becoming the new oldest:
    //   existing_earliest.endorsed_key == NEW.endorsing_key
    void process_extension(const ccf::CoseEndorsement& endorsement)
    {
      const auto from = endorsement.endorsement_epoch_begin.seqno;

      if (is_self_endorsement(endorsement))
      {
        {
          std::lock_guard<std::mutex> g(chain_mutex);
          if (endorsements.find(from) == endorsements.end())
          {
            fail_fetching(fmt::format(
              "Extension: fetched self-endorsement with seqno {} which has "
              "not been seen",
              from));
          }
        }
        LOG_INFO_FMT(
          "COSE endorsement chain extended back to self-endorsement at {}",
          from);
        complete_fetching_ready();
        return;
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        fail_fetching(fmt::format(
          "Extension: fetched endorsement at {} has no epoch end", from));
        return; // to silence clang-tidy unchecked optional
      }

      // Snapshot the bit of state we need under the lock, then run the
      // crypto verification (signature + DER comparison) without the
      // lock to keep the RPC read path responsive.
      std::optional<ccf::CoseEndorsement> existing_earliest_snapshot;
      std::vector<uint8_t> expected_new_endorsing_key_der;
      TxID current_service_from_snapshot;
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        if (!current_service_from.has_value())
        {
          fail_fetching(
            "Extension: unset current_service_from when extending chain");
          return; // to silence clang-tidy unchecked optional
        }
        if (from >= earliest_endorsed_seq)
        {
          fail_fetching(fmt::format(
            "Extension: fetched service endorsement with seqno {} which is "
            "not earlier than the current earliest known {}",
            from,
            earliest_endorsed_seq));
        }
        if (endorsements.find(from) != endorsements.end())
        {
          fail_fetching(fmt::format(
            "Extension: fetched service endorsement with seqno {} which "
            "already exists",
            from));
        }
        current_service_from_snapshot = *current_service_from;
        if (!endorsements.empty())
        {
          existing_earliest_snapshot = endorsements.begin()->second;
          auto trusted_it = trusted_keys.find(
            existing_earliest_snapshot->endorsement_epoch_begin.seqno);
          if (trusted_it == trusted_keys.end())
          {
            fail_fetching(fmt::format(
              "Extension: missing trusted key entry for existing earliest "
              "endorsement at seqno {}",
              existing_earliest_snapshot->endorsement_epoch_begin.seqno));
            return; // to silence clang-tidy unchecked iterator
          }
          expected_new_endorsing_key_der = trusted_it->second->public_key_der();
        }
        else
        {
          expected_new_endorsing_key_der =
            network_identity->get_key_pair()->public_key_der();
        }
      }

      ccf::crypto::ECPublicKeyPtr new_trusted_key;
      try
      {
        if (existing_earliest_snapshot.has_value())
        {
          validate_chain_integrity(*existing_earliest_snapshot, endorsement);
        }
        else
        {
          std::map<SeqNo, CoseEndorsement> single_entry{{from, endorsement}};
          validate_chain_front_connection(
            single_entry, current_service_from_snapshot);
        }

        auto verifier =
          ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key);
        std::span<uint8_t> endorsed_key;
        if (!verifier->verify(endorsement.endorsement, endorsed_key))
        {
          throw std::logic_error(fmt::format(
            "Extension: endorsement from {} to {} failed signature "
            "verification",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end)));
        }
        if (
          endorsement.endorsing_key.size() !=
            expected_new_endorsing_key_der.size() ||
          !std::equal(
            endorsement.endorsing_key.begin(),
            endorsement.endorsing_key.end(),
            expected_new_endorsing_key_der.begin()))
        {
          throw std::logic_error(fmt::format(
            "Extension: endorsement from {} to {} signed by key {} does "
            "not chain with the expected next key {}",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end),
            ccf::ds::to_hex(endorsement.endorsing_key),
            ccf::ds::to_hex(expected_new_endorsing_key_der)));
        }
        new_trusted_key = ccf::crypto::make_ec_public_key(endorsed_key);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      {
        std::lock_guard<std::mutex> g(chain_mutex);
        endorsements.insert({from, endorsement});
        trusted_keys.insert({from, std::move(new_trusted_key)});
        earliest_endorsed_seq = from;
      }

      LOG_INFO_FMT(
        "COSE endorsement chain extended backward to seqno {} (epoch {} - {})",
        from,
        endorsement.endorsement_epoch_begin.to_str(),
        endorsement.endorsement_epoch_end->to_str());

      if (!endorsement.previous_version.has_value())
      {
        fail_fetching(fmt::format(
          "Extension: non-self-endorsement at seqno {} unexpectedly has no "
          "previous_version",
          from));
        return; // to silence clang-tidy unchecked optional
      }
      fetch_next_at(*endorsement.previous_version);
    }

    void fetch_next_at(ccf::SeqNo seq)
    {
      // Drop stale callbacks from cycles that have already ended. This
      // happens when, for example, the previous cycle hit its retry
      // budget and another cycle has not yet been triggered, but a
      // delayed task scheduled before the cycle ended still fires.
      if (!fetch_active.load())
      {
        return;
      }

      auto state = historical_cache->get_state_at(
        ccf::historical::CompoundHandle{
          ccf::historical::RequestNamespace::System, seq},
        seq);
      if (!state)
      {
        retry_fetch_next(seq);
        return;
      }

      if (!state->store)
      {
        fail_fetching(fmt::format(
          "Fetched historical state with seqno {} with missing store", seq));
      }
      auto htx = state->store->create_read_only_tx();
      const auto endorsement =
        htx
          .template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();

      if (!endorsement.has_value())
      {
        fail_fetching(
          fmt::format("Fetched COSE endorsement for {} is invalid", seq));
        return; // to silence clang-tidy unchecked optional
      }

      try
      {
        validate_fetched_endorsement(endorsement.value());
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      // Successful fetch — reset the per-seq attempt counter so the next
      // predecessor (a different seqno) starts fresh.
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        fetch_attempts = 0;
      }
      process_endorsement(endorsement.value());
    }

    void retry_fetch_next(ccf::SeqNo seq)
    {
      bool exhausted = false;
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        ++fetch_attempts;
        if (fetch_attempts >= MAX_FETCH_ATTEMPTS)
        {
          exhausted = true;
        }
      }

      if (exhausted)
      {
        LOG_FAIL_FMT(
          "Could not fetch previous service identity endorsement at seqno {} "
          "after {} attempts at {}ms intervals. Cycle ends; status is "
          "PartialReady. Callers may invoke trigger_extension to retry.",
          seq,
          MAX_FETCH_ATTEMPTS,
          RETRY_INTERVAL.count());
        if (fetch_status.load() == FetchStatus::Fetching)
        {
          complete_bootstrap_partial();
        }
        else
        {
          complete_extension_partial();
        }
        return;
      }

      auto task = ccf::tasks::make_basic_task(
        [this, seq]() { this->fetch_next_at(seq); });
      {
        std::lock_guard<std::mutex> g(chain_mutex);
        poll_task = task;
      }
      ccf::tasks::add_delayed_task(std::move(task), RETRY_INTERVAL);
    }
  };
}
