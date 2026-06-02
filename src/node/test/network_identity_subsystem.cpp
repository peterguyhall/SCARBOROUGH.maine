// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/rpc/network_identity_chain_helpers.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <doctest/doctest.h>

using namespace std::chrono_literals;

namespace
{
  // Build a synthetic CoseEndorsement covering range [begin_view:begin_seqno,
  // end_view:end_seqno]. Signature/key payloads are left empty: only the
  // range fields are exercised by the pure-helper validators tested here.
  ccf::CoseEndorsement make_range_endorsement(
    ccf::View begin_view,
    ccf::SeqNo begin_seqno,
    ccf::View end_view,
    ccf::SeqNo end_seqno,
    std::optional<ccf::kv::Version> previous_version = ccf::kv::Version{
      1} /* default: not self-endorsement */)
  {
    ccf::CoseEndorsement e;
    e.endorsement_epoch_begin = ccf::TxID{begin_view, begin_seqno};
    e.endorsement_epoch_end = ccf::TxID{end_view, end_seqno};
    e.previous_version = previous_version;
    return e;
  }

  ccf::CoseEndorsement make_self_endorsement(
    ccf::View begin_view, ccf::SeqNo begin_seqno)
  {
    ccf::CoseEndorsement e;
    e.endorsement_epoch_begin = ccf::TxID{begin_view, begin_seqno};
    // Self-endorsements have neither epoch_end nor previous_version
    e.endorsement_epoch_end = std::nullopt;
    e.previous_version = std::nullopt;
    return e;
  }
}

TEST_CASE("is_self_endorsement detects absence of previous_version")
{
  REQUIRE(ccf::is_self_endorsement(make_self_endorsement(2, 10)));
  REQUIRE_FALSE(ccf::is_self_endorsement(make_range_endorsement(3, 11, 3, 20)));
}

TEST_CASE("is_ill_formed detects inverted range")
{
  REQUIRE(ccf::is_ill_formed(make_range_endorsement(3, 20, 3, 10)));
  REQUIRE_FALSE(ccf::is_ill_formed(make_range_endorsement(3, 10, 3, 20)));
  // Self-endorsement has no epoch_end, so it is never ill-formed
  REQUIRE_FALSE(ccf::is_ill_formed(make_self_endorsement(2, 10)));
}

TEST_CASE("validate_chain_integrity accepts adjacent endorsements")
{
  // older covers [v=2, 10..20]; newer starts at v=3, seqno=21.
  // The view rule is: newer.begin.view - aft::starting_view_change ==
  // older.end.view, and newer.begin.seqno - 1 == older.end.seqno.
  auto older = make_range_endorsement(2, 10, 2, 20);
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 21, 3, 30);

  REQUIRE_NOTHROW(ccf::validate_chain_integrity(newer, older));
}

TEST_CASE("validate_chain_integrity rejects view discontinuity")
{
  auto older = make_range_endorsement(2, 10, 2, 20);
  // newer.begin.view should be 2 + starting_view_change; use a wrong value
  auto newer =
    make_range_endorsement(2 + aft::starting_view_change + 1, 21, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::validate_chain_integrity(newer, older), std::logic_error);
}

TEST_CASE("validate_chain_integrity rejects seqno gap")
{
  auto older = make_range_endorsement(2, 10, 2, 20);
  // seqno gap: newer.begin.seqno should be 21
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 22, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::validate_chain_integrity(newer, older), std::logic_error);
}

TEST_CASE("validate_chain_integrity rejects older with no epoch_end")
{
  ccf::CoseEndorsement older = make_range_endorsement(2, 10, 2, 20);
  older.endorsement_epoch_end = std::nullopt;
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 21, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::validate_chain_integrity(newer, older), std::logic_error);
}

TEST_CASE("validate_chain_integrity_pairwise no-op for 0 or 1 entries")
{
  std::map<ccf::SeqNo, ccf::CoseEndorsement> empty;
  REQUIRE_NOTHROW(ccf::validate_chain_integrity_pairwise(empty));

  std::map<ccf::SeqNo, ccf::CoseEndorsement> one;
  one.insert({10, make_range_endorsement(2, 10, 2, 20)});
  REQUIRE_NOTHROW(ccf::validate_chain_integrity_pairwise(one));
}

TEST_CASE("validate_chain_integrity_pairwise walks the map in order")
{
  std::map<ccf::SeqNo, ccf::CoseEndorsement> chain;
  // Three adjacent endorsements
  chain.insert({10, make_range_endorsement(2, 10, 2, 20)});
  chain.insert(
    {21, make_range_endorsement(2 + aft::starting_view_change, 21, 3, 30)});
  chain.insert(
    {31, make_range_endorsement(3 + aft::starting_view_change, 31, 4, 40)});

  REQUIRE_NOTHROW(ccf::validate_chain_integrity_pairwise(chain));

  // Break the middle pair by removing the epoch_end on entry 21
  chain.at(21).endorsement_epoch_end = std::nullopt;
  REQUIRE_THROWS_AS(
    ccf::validate_chain_integrity_pairwise(chain), std::logic_error);
}

TEST_CASE(
  "validate_chain_front_connection requires current_service_from to "
  "immediately follow the last endorsement")
{
  std::map<ccf::SeqNo, ccf::CoseEndorsement> chain;
  chain.insert({10, make_range_endorsement(2, 10, 2, 20)});

  // current_service_from must have view = 2 + starting_view_change and
  // seqno = 21 to be adjacent.
  ccf::TxID good{2 + aft::starting_view_change, 21};
  REQUIRE_NOTHROW(ccf::validate_chain_front_connection(chain, good));

  ccf::TxID bad_seqno{2 + aft::starting_view_change, 22};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(chain, bad_seqno), std::logic_error);

  ccf::TxID bad_view{3 + aft::starting_view_change, 21};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(chain, bad_view), std::logic_error);
}

TEST_CASE("validate_chain_front_connection no-op for empty chain")
{
  // The partial-chain "we couldn't fetch any predecessor" case must not
  // throw here: there is nothing in the chain to connect to.
  std::map<ccf::SeqNo, ccf::CoseEndorsement> empty;
  ccf::TxID any{2, 100};
  REQUIRE_NOTHROW(ccf::validate_chain_front_connection(empty, any));
}

TEST_CASE("validate_chain_front_connection rejects last with no epoch_end")
{
  std::map<ccf::SeqNo, ccf::CoseEndorsement> chain;
  ccf::CoseEndorsement bad = make_range_endorsement(2, 10, 2, 20);
  bad.endorsement_epoch_end = std::nullopt;
  chain.insert({10, bad});

  ccf::TxID after{2 + aft::starting_view_change, 21};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(chain, after), std::logic_error);
}
