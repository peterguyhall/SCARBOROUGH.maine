// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"

#include <exception>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity;

  /// A single raw COSE endorsement, stored as an opaque byte vector.
  using RawCoseEndorsement = std::vector<uint8_t>;
  /// An ordered chain of raw COSE endorsements.
  using CoseEndorsementsChain = std::vector<RawCoseEndorsement>;

  /// Status of the network identity endorsement fetching process.
  enum class FetchStatus : uint8_t
  {
    Fetching, ///< Subsystem is actively walking the endorsement chain; no
              ///< chain data is yet available to read.
    Ready, ///< The full endorsement chain has been fetched and validated;
           ///< all reads return their definitive answers.
    PartialReady, ///< A bounded fetch attempt for some predecessor endorsement
                  ///< chunk exhausted its retry budget without succeeding. The
                  ///< chain data that was fetched is available for reads.
                  ///< Background polling is stopped; callers may call
                  ///< @ref NetworkIdentitySubsystemInterface::trigger_extension
                  ///< to retry fetching the missing predecessor.
    Failed ///< Endorsement-chain validation failed irrecoverably (e.g.
           ///< signature mismatch or chain-integrity violation). The
           ///< subsystem treats this as fatal and the node will abort.
  };

  /// Map from sequence number to EC public key, representing the trusted
  /// network identity keys over the history of the service.
  using TrustedKeys = std::map<ccf::SeqNo, ccf::crypto::ECPublicKeyPtr>;

  /// Exception thrown when identity data is requested before the
  /// asynchronous identity-history-fetching process has completed.
  struct IdentityHistoryNotFetched : public std::exception
  {
    std::string msg;

    IdentityHistoryNotFetched(std::string msg) : msg(std::move(msg)) {}

    [[nodiscard]] const char* what() const noexcept override
    {
      return msg.c_str();
    }
  };

  /// Interface for accessing the network identity subsystem, which manages
  /// the service's cryptographic identity and its historical trusted keys.
  class NetworkIdentitySubsystemInterface : public ccf::AbstractNodeSubSystem
  {
  public:
    ~NetworkIdentitySubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "NetworkIdentity";
    }

    /// Returns a reference to the current network identity.
    virtual const std::unique_ptr<NetworkIdentity>& get() = 0;

    /// Returns the current status of endorsement fetching.
    [[nodiscard]] virtual FetchStatus endorsements_fetching_status() const = 0;

    /// If the subsystem is currently in @ref FetchStatus::PartialReady,
    /// schedule a fresh attempt to fetch the next missing predecessor
    /// endorsement and transition to @ref FetchStatus::Fetching. No-op in
    /// any other state. Thread-safe and idempotent: concurrent callers
    /// trigger at most one extension cycle.
    virtual void trigger_extension() = 0;

    /// Returns the COSE endorsements chain for the given sequence number.
    ///
    /// @returns A vector of raw COSE endorsements, oldest-first, leading to
    /// the current service identity. May be empty for the current epoch or
    /// when the chain has been fully walked and the given seqno is
    /// pre-history. Returns std::nullopt if no chain is available because
    /// the subsystem is still fetching (@ref FetchStatus::Fetching) or
    /// because it is partial and the chain it has does not cover the
    /// requested seqno (@ref FetchStatus::PartialReady). In the latter
    /// case, callers may invoke @ref trigger_extension to ask the
    /// subsystem to attempt to extend the chain.
    ///
    /// @throws IdentityHistoryNotFetched if fetching status is
    /// @ref FetchStatus::Fetching.
    [[nodiscard]] virtual std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const = 0;

    /// Returns the trusted EC public key that was active at the given
    /// sequence number, or nullptr if the sequence number precedes the
    /// earliest known trusted key.
    ///
    /// @note In @ref FetchStatus::PartialReady the earliest known trusted
    /// key may correspond to a more-recent epoch than expected. Callers
    /// that need older keys can invoke @ref trigger_extension and retry.
    ///
    /// @throws IdentityHistoryNotFetched if fetching status is
    /// @ref FetchStatus::Fetching.
    /// @throws std::logic_error if no trusted keys have been fetched, or if
    /// internal key resolution is inconsistent.
    [[nodiscard]] virtual ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const = 0;

    /// Returns all trusted network identity keys as a map from sequence
    /// number to EC public key.
    ///
    /// @note In @ref FetchStatus::PartialReady the returned map only
    /// contains the keys whose endorsements were successfully validated;
    /// older epochs are silently omitted until a successful extension.
    /// Callers can invoke @ref trigger_extension to ask the subsystem to
    /// attempt to fetch them.
    ///
    /// @throws IdentityHistoryNotFetched if fetching status is
    /// @ref FetchStatus::Fetching.
    [[nodiscard]] virtual TrustedKeys get_trusted_keys() const = 0;
  };
}
