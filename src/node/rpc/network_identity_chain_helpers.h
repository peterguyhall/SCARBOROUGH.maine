// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Pure helpers used by NetworkIdentitySubsystem. Kept in a separate
// lightweight header so unit tests can exercise them without depending on
// the heavyweight subsystem (which transitively pulls in node state,
// historical queries, etc).

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/ec_public_key.h"
#include "ccf/ds/hex.h"
#include "ccf/network_identity_interface.h"
#include "ccf/tx_id.h"
#include "consensus/aft/raft_types.h"
#include "ds/internal_logger.h"
#include "node/cose_common.h"
#include "node/identity.h"
#include "service/tables/previous_service_identity.h"

#include <algorithm>
#include <chrono>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>

namespace ccf
{
  inline std::string format_epoch(const std::optional<ccf::TxID>& epoch_end)
  {
    return epoch_end.has_value() ? epoch_end->to_str() : "null";
  }

  inline bool is_self_endorsement(const ccf::CoseEndorsement& endorsement)
  {
    return !endorsement.previous_version.has_value();
  }

  inline bool is_ill_formed(const ccf::CoseEndorsement& endorsement)
  {
    return endorsement.endorsement_epoch_end.has_value() &&
      endorsement.endorsement_epoch_end->seqno <
      endorsement.endorsement_epoch_begin.seqno;
  }

  inline void validate_fetched_endorsement(
    const ccf::CoseEndorsement& endorsement)
  {
    LOG_INFO_FMT(
      "Validating fetched endorsement from {} to {}",
      endorsement.endorsement_epoch_begin.to_str(),
      format_epoch(endorsement.endorsement_epoch_end));

    if (!is_self_endorsement(endorsement))
    {
      const auto [from, to] =
        ccf::crypto::extract_cose_endorsement_validity(endorsement.endorsement);

      const auto from_txid = ccf::TxID::from_str(from);
      if (!from_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_BEGIN));
      }

      const auto to_txid = ccf::TxID::from_str(to);
      if (!to_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_END));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        throw std::logic_error(
          "COSE endorsement does not contain epoch end in the table entry");
      }
      if (
        endorsement.endorsement_epoch_begin != *from_txid ||
        *endorsement.endorsement_epoch_end != *to_txid)
      {
        throw std::logic_error(fmt::format(
          "COSE endorsement fetched but range is invalid, epoch begin {}, "
          "epoch end {}, header epoch begin: {}, header epoch end: {}",
          endorsement.endorsement_epoch_begin.to_str(),
          endorsement.endorsement_epoch_end->to_str(),
          from,
          to));
      }
    }
  }

  inline void validate_chain_integrity(
    const ccf::CoseEndorsement& newer, const ccf::CoseEndorsement& older)
  {
    if (!older.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "from {} does not have an epoch end",
        older.endorsement_epoch_begin.to_str()));
    }

    if (
      newer.endorsement_epoch_begin.view - aft::starting_view_change !=
        older.endorsement_epoch_end->view ||
      newer.endorsement_epoch_begin.seqno - 1 !=
        older.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "epoch end {} is not chained with newer endorsement epoch begin {}",
        older.endorsement_epoch_end->to_str(),
        newer.endorsement_epoch_begin.to_str()));
    }
  }

  // Pairwise chain-integrity check across all adjacent endorsements in the map.
  inline void validate_chain_integrity_pairwise(
    const std::map<SeqNo, CoseEndorsement>& endorsements_in)
  {
    if (endorsements_in.size() < 2)
    {
      return;
    }
    auto next = endorsements_in.begin();
    auto prev = next++;
    while (next != endorsements_in.end())
    {
      validate_chain_integrity(next->second, prev->second);
      ++prev;
      ++next;
    }
  }

  // Verify the newest endorsement in the chain immediately precedes the
  // current service start. Required regardless of whether the chain reaches
  // a self-endorsement at the back.
  inline void validate_chain_front_connection(
    const std::map<SeqNo, CoseEndorsement>& endorsements_in,
    const ccf::TxID& current_service_from)
  {
    if (endorsements_in.empty())
    {
      return;
    }
    const auto& last = endorsements_in.rbegin()->second;
    if (!last.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "The last fetched endorsement at {} has no epoch end",
        last.endorsement_epoch_begin.seqno));
    }
    if (
      current_service_from.view - aft::starting_view_change !=
        last.endorsement_epoch_end->view ||
      current_service_from.seqno - 1 != last.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, the current service "
        "start at {} is not chained with previous endorsement ending at {}",
        current_service_from.to_str(),
        last.endorsement_epoch_end->to_str()));
    }
  }

  // Build the trusted-key chain from an ordered endorsements map plus the
  // current service public key. Throws on any signature failure or
  // key-chain mismatch. Returns a fresh TrustedKeys map.
  inline TrustedKeys build_trusted_keys(
    const std::map<SeqNo, CoseEndorsement>& endorsements_in,
    const std::vector<uint8_t>& current_service_pkey_der,
    const ccf::TxID& current_service_from)
  {
    TrustedKeys result;
    std::span<const uint8_t> previous_key_der{};
    for (const auto& [seqno, endorsement] : endorsements_in)
    {
      auto verifier =
        ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key);
      std::span<uint8_t> endorsed_key;
      if (!verifier->verify(endorsement.endorsement, endorsed_key))
      {
        throw std::logic_error(fmt::format(
          "COSE endorsement chain integrity is violated, endorsement from {} "
          "to {} failed signature verification",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      result.insert(
        {endorsement.endorsement_epoch_begin.seqno,
         ccf::crypto::make_ec_public_key(endorsed_key)});

      if (
        !previous_key_der.empty() &&
        !std::equal(
          previous_key_der.begin(),
          previous_key_der.end(),
          endorsed_key.begin(),
          endorsed_key.end()))
      {
        throw std::logic_error(fmt::format(
          "Endorsement from {} to {} over public key {} doesn't chain with "
          "the previous endorsement with key {}",
          endorsement.endorsement_epoch_begin.seqno,
          format_epoch(endorsement.endorsement_epoch_end),
          ccf::ds::to_hex(endorsed_key),
          ccf::ds::to_hex(previous_key_der)));
      }

      previous_key_der = endorsement.endorsing_key;
    }

    if (
      !previous_key_der.empty() &&
      !std::equal(
        previous_key_der.begin(),
        previous_key_der.end(),
        current_service_pkey_der.begin(),
        current_service_pkey_der.end()))
    {
      throw std::logic_error(fmt::format(
        "Current service identity public key {} does not match the last "
        "endorsing key {}",
        ccf::ds::to_hex(current_service_pkey_der),
        ccf::ds::to_hex(previous_key_der)));
    }

    result.insert(
      {current_service_from.seqno,
       ccf::crypto::make_ec_public_key(current_service_pkey_der)});

    return result;
  }
}