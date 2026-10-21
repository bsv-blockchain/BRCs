#!/usr/bin/env python3
"""Audit BRC-234 data and synthetic conformance vectors with Python 3.

Requires hashlib RIPEMD160 support. Does not contact the network, alter files,
validate consensus/signatures, or certify an operating indexer.
"""
import hashlib
import json
import math
import re
from calendar import monthrange
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / 'opinions/media/0234'
schedule = json.loads((DATA / 'schedule.json').read_text())
vectors = json.loads((DATA / 'conformance-vectors.json').read_text())
rows = schedule['rows']
spec = (ROOT / 'opinions/0234.md').read_text()
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
totals = {}


def sha2(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def encode58(b):
    n = int.from_bytes(b, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = alphabet[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + s


def valid_address(a):
    if not a or any(c not in alphabet for c in a):
        return False
    n = 0
    for c in a:
        n = n * 58 + alphabet.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    raw = b'\0' * (len(a) - len(a.lstrip('1'))) + raw
    return (len(raw) == 25 and raw[0] == 0 and sha2(raw[:21])[:4] == raw[21:]
            and encode58(raw) == a)


def address_match(a, stage):
    if not valid_address(a):
        return False
    rule = rows[stage]['addressRule']
    if '[' not in rule:
        return a.startswith(rule)
    p, chars = rule[:-1].split('[')
    return a.startswith(p) and len(a) > len(p) and a[len(p)] in chars


def txid_match(t, stage):
    if re.fullmatch('[0-9a-fA-F]{64}', t) is None:
        return False
    bits = ''.join(f'{b:08b}' for b in bytes.fromhex(t))
    target = '1001' * 64
    n = rows[stage]['txidBits']
    return bits[:n] == target[:n]


def transaction_match(tx, stage):
    return txid_match(tx['txid'], stage) and (stage <= 12 or tx['version'] == 1)


assert [r['stage'] for r in rows] == list(range(28))
assert rows[-1]['txidBits'] == 52 and rows[-1]['volume'] == 8192000000
assert schedule['recommendedRecoveryRetentionBlocks'] == vectors['recommendedRecoveryRetentionBlocks'] == 100
assert schedule['noticePeriodSeconds'] == 1209600
for r in rows:
    assert r['requiredTransactionVersion'] == (None if r['stage'] <= 12 else 1)
    assert r['spendAccountingMode'] == ('all_confirmed_spends' if r['stage'] <= 12
                                       else 'qualifying_version_1_txids_only')
for c in vectors['transactionEligibilityCases']:
    assert transaction_match(c, c['stage']) == c['expectedEligible'], c
totals['transaction_version_eligibility_cases'] = len(vectors['transactionEligibilityCases'])
for c in vectors['versionRetrievalCases']:
    eligible = transaction_match(c, c['currentStage'])
    if c['family'] != 'txid':
        eligible = eligible and c['identifierEligible']
    assert eligible == c['expectedEligible'], c
totals['current_version_retrieval_cases'] = len(vectors['versionRetrievalCases'])
for c in vectors['addressPredicateCases']:
    assert address_match(c['address'], c['stage']) == c['expectedMatches'], c
totals['address_predicate_cases'] = len(vectors['addressPredicateCases'])
for c in vectors['txidPredicateCases']:
    assert txid_match(c['txid'], c['stage']) == c['expectedMatches'], c
totals['txid_predicate_cases'] = len(vectors['txidPredicateCases'])

def script_hash(s):
    return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(s)).digest()).hexdigest()


def script_match(h, stage):
    if re.fullmatch('[0-9a-fA-F]{40}', h) is None:
        return False
    value = int(h, 16)
    bits = rows[stage]['scriptHashBits']
    return value >> (160-bits) == int('7'*40, 16) >> (160-bits)


for c in vectors['scriptHashPredicateCases']:
    assert script_match(c['scriptHash'], c['stage']) == c['expectedMatches'], c
totals['script_hash_predicate_cases'] = len(vectors['scriptHashPredicateCases'])
for c in vectors['scriptHashMappingCases']:
    assert script_hash(c['lockingScript']) == c['expectedHash160'], c
    native_digest = bytes.fromhex(c['nativeSha256'])
    assert hashlib.sha256(bytes.fromhex(c['lockingScript'])).digest() == native_digest, c
    assert hashlib.new('ripemd160', native_digest).hexdigest() == c['expectedHash160'], c
    assert bytes.fromhex(c['nativeReversedSha256'])[::-1] == native_digest, c
totals['script_hash_mapping_cases'] = len(vectors['scriptHashMappingCases'])

# Independent exact count: binary search the monotone checked payload for
# each base-58 numeral interval, rather than approximate character weights.
def checked_payload(h):
    body = b'\0' + h.to_bytes(20, 'big')
    return (h << 32) | int.from_bytes(sha2(body)[:4], 'big')


def lower_bound_payload(n):
    lo, hi = 1 << 152, 1 << 160
    while lo < hi:
        mid = (lo + hi) // 2
        if checked_payload(mid) < n:
            lo = mid + 1
        else:
            hi = mid
    return lo


def count_prefix(prefix):
    body = prefix[1:]
    value = 0
    for char in body:
        value = value * 58 + alphabet.index(char)
    total = 0
    for length in range(len(body), 34):
        unit = 58 ** (length - len(body))
        low, high = value * unit, (value + 1) * unit
        low, high = max(low, 1 << 184), min(high, 1 << 192)
        if low < high:
            total += lower_bound_payload(high) - lower_bound_payload(low)
    return total


for r in rows:
    rule = r['addressRule']
    if r['stage'] == 0:
        count = 1 << 160
    elif '[' in rule:
        p, chars = rule[:-1].split('[')
        count = sum(count_prefix(p + c) for c in chars)
    else:
        count = count_prefix(rule)
    assert count == int(r['eligibleHash160Values']), (r['stage'], count, r['eligibleHash160Values'])
    assert math.isclose((1 << 160) / count, r['addressTrials'], rel_tol=1e-12)
    assert math.isclose(math.log2((1 << 160) / count), r['addressWorkBits'], abs_tol=1e-12)
    assert r['txidTrials'] == 2 ** r['txidBits']
    bits = r['scriptHashBits']
    assert count * (1 << bits) >= 1 << 160
    assert bits == 0 or count * (1 << (bits-1)) < 1 << 160
    assert int(r['scriptHashTrials']) == 1 << bits
    assert (1 << 160) <= count * int(r['scriptHashTrials']) < (1 << 161)
totals['exact_address_space_counts'] = len(rows)

# Verify set nesting directly, including both bracket sets and full prefixes.
def alternatives(rule):
    if '[' not in rule:
        return [rule]
    p, chars = rule[:-1].split('[')
    return [p + c for c in chars]


for prior, following in zip(rows, rows[1:]):
    assert all(any(q.startswith(p) for p in alternatives(prior['addressRule']))
               for q in alternatives(following['addressRule']))
    assert following['txidBits'] >= prior['txidBits']
    assert following['scriptHashBits'] >= prior['scriptHashBits']
    assert following['volume'] > prior['volume']


def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def add_months(t, n):
    year, month0 = divmod(t.year * 12 + t.month - 1 + n, 12)
    return t.replace(year=year, month=month0+1, day=min(t.day, monthrange(year, month0+1)[1]))


weights = [11 ** i * 10 ** (25-i) for i in range(26)]
weight_total = sum(weights)
assert weight_total == 1091817653772720942460132761


def gates(anchor):
    start, end = add_months(anchor, 6), add_months(anchor, 78)
    seconds = int((end-start).total_seconds())
    out = {1: start}
    cumulative = 0
    for stage, w in enumerate(weights, 2):
        cumulative += w
        offset = (seconds * cumulative + weight_total - 1) // weight_total
        out[stage] = start + timedelta(seconds=offset)
    assert out[27] == end
    return out


for c in vectors['calendarCases']:
    calc = gates(parse_iso(c['anchor']))
    for stage, value in c['expectedGateTimes'].items():
        assert calc[int(stage)] == parse_iso(value), (c['anchor'], stage)
totals['exact_calendar_gates'] = 27 * len(vectors['calendarCases'])
for c in vectors['gateCases']:
    times = gates(parse_iso(c['anchor']))
    candidate = max([0] + [s for s in range(1, 28)
        if parse_iso(c['mtp']) >= times[s] and int(c['volume']) >= rows[s]['volume']])
    assert candidate == c['expectedCandidate'], c
totals['time_and_volume_boundary_cases'] = len(vectors['gateCases'])

# Count decoded block entries independently of filtering and ledger fixtures.
# Tip changes exercise rollback/addition as well as fresh ancestry reconstruction.
volume_observations = 0
for c in vectors['volumeCountCases']:
    blocks = {b['blockId']: b for b in c['blocks']}
    assert len(blocks) == len(c['blocks']), c['id']
    for b in blocks.values():
        assert sum(tx['coinbase'] for tx in b['transactions']) == 1, b
    def counted_path(tip):
        path = []
        b = blocks[tip]
        while b['height'] > 1000000:
            path.append(b['blockId'])
            parent = blocks[b['parent']]
            assert parent['height'] == b['height'] - 1, b
            b = parent
        assert b['height'] == 1000000, b
        return b['blockId'], list(reversed(path))
    def contribution(block_id):
        return sum(1 for tx in blocks[block_id]['transactions'] if not tx['coinbase'])
    prior_anchor, prior_path, rolling = None, [], 0
    for observation in c['acceptedTipObservations']:
        anchor, path = counted_path(observation['tip'])
        if anchor != prior_anchor:
            rolling, prior_path = 0, []
        common = 0
        while common < min(len(path), len(prior_path)) and path[common] == prior_path[common]:
            common += 1
        rolling -= sum(contribution(b) for b in prior_path[common:])
        rolling += sum(contribution(b) for b in path[common:])
        # Fresh reconstruction uses total block entries minus one coinbase each.
        reconstructed = sum(len(blocks[b]['transactions']) - 1 for b in path)
        assert rolling == reconstructed == observation['expectedVolume'], (c['id'], observation, rolling)
        prior_anchor, prior_path = anchor, path
        volume_observations += 1
totals['block_volume_count_traces'] = len(vectors['volumeCountCases'])
totals['block_volume_count_observations'] = volume_observations

# Cross-check both Markdown tables and all approximate display calculations.
table1 = [line for line in spec.splitlines() if re.match(r'\| \d+ \|', line)][:28]
for r, line in zip(rows, table1):
    cells = [x.strip() for x in line.split('|')[1:-1]]
    assert cells == [str(r['stage']), f"`{r['addressRule']}`", f"`{r['scriptHashRule']}` ({r['scriptHashBits']})", str(r['txidBits']), 'any' if r['stage'] <= 12 else '1', f"{r['volume']:,}"], cells
table2 = [line for line in spec.splitlines() if re.match(r'\| \d+ \|', line)][28:]
assert len(table1) == 28 and len(table2) == 27
for r, line in zip(rows[1:], table2):
    cells = [x.strip().strip('`') for x in line.split('|')[1:-1]]
    assert cells[:4] == [str(r['stage']), r['compactAddressRule'], r['scriptHashRule'], r['txidRule']]
    assert cells[4:6] == [f"{r['nominalElapsedMonths']:.2f}", f"{r['nominalIntervalMonths']:.2f}"]
    assert cells[6] == f"{r['volume']:,}"
    assert float(cells[7]) == float(f"{r['addressTrials']:.3g}")
    assert float(cells[8]) == float(f"{int(r['scriptHashTrials']):.3g}")
    assert float(cells[9]) == float(f"{r['txidTrials']:.3g}")
    cumulative = sum(weights[:r['stage']-1])
    expected = 6 + 72 * cumulative / weight_total
    assert math.isclose(r['nominalElapsedMonths'], expected, abs_tol=1e-10)
    assert int(r['postGraceWeightNumerator']) == cumulative
    assert int(r['postGraceWeightDenominator']) == weight_total
totals['markdown_schedule_rows_checked'] = len(table1) + len(table2)

for c in vectors['noticeRoundCases']:
    times = gates(parse_iso(c['anchor']))
    current = 0
    # An independent scheduling form: a pending event is scheduled for the
    # first next block after its deadline has been observed. New eligibility
    # cannot modify an already scheduled event.
    pending = None
    activate_next = None
    stages, targets, notice_active, remaining_seconds = [], [], [], []
    for b in c['acceptedBlocks']:
        if activate_next is not None:
            current = activate_next
            activate_next = None
            pending = None
        t = parse_iso(b['mtp'])
        candidate = max([0] + [s for s in range(1,28)
            if t >= times[s] and int(b['volume']) >= rows[s]['volume']])
        if not c.get('anchorOnAcceptedChain', True):
            candidate = 0
        if pending is None and candidate > current:
            pending = {'target':candidate, 'deadline':t+timedelta(days=14)}
        if pending and t >= pending['deadline']:
            activate_next = pending['target']
        stages.append(current)
        targets.append(pending['target'] if pending else None)
        notice_active.append(pending is not None)
        remaining_seconds.append(max(0, int((pending['deadline'] - t).total_seconds()))
                                 if pending else None)
    assert stages == c['expectedStages'], (c['id'], stages)
    assert targets == c['expectedPendingTargets'], (c['id'], targets)
    if 'expectedNoticeRoundActive' in c:
        assert notice_active == c['expectedNoticeRoundActive'], (c['id'], notice_active)
    if 'expectedRemainingMtpSeconds' in c:
        assert remaining_seconds == c['expectedRemainingMtpSeconds'], (c['id'], remaining_seconds)
    if 'expectedFinalDeadline' in c:
        assert pending['deadline'] == parse_iso(c['expectedFinalDeadline'])
    if 'expectedLateJoinStage' in c:
        assert current == c['expectedLateJoinStage']
totals['deterministic_notice_chain_traces'] = len(vectors['noticeRoundCases'])

# Independent decoded-effect replay: discard observed orphan and mempool lists.
# These synthetic fixtures intentionally do not assert full consensus validity.
for c in vectors['balanceTraceCases']:
    outputs = {}
    admitted = {}
    ledger_snapshots = {}
    ledger_view = c.get('ledgerView', 'baseline')
    family = c['keyFamily']
    query = c['queryKey']
    def get_key(out):
        return out.get('address') if family == 'address' else script_hash(out['lockingScript'])
    def matches(k, s):
        return address_match(k, s) if family == 'address' else script_match(k, s)
    for block in c['acceptedBlocks']:
        stage = block['eventStage']
        for tx in block['transactions']:
            for inp in tx['inputs']:
                key = (inp['txid'], inp['index'])
                assert key in outputs, (c['id'], key)
                outputs.pop(key)
                if (stage <= 12 or transaction_match(tx, stage)
                        or (ledger_view == 'enhanced' and c.get('extraSpendsVerified'))):
                    admitted.pop(key, None)
            for index, out in enumerate(tx['outputs']):
                key = (tx['txid'], index)
                outputs[key] = out
                if transaction_match(tx, stage) and matches(get_key(out), stage):
                    admitted[key] = out
        ledger_snapshots[block['blockId']] = (stage, admitted.copy())
    current_stage = stage
    snapshot_id = c.get('snapshotBlockId', c['acceptedBlocks'][-1]['blockId'])
    snapshot = ledger_snapshots.get(snapshot_id)
    if not matches(query, stage):
        result = {'state': 'outside_free_coverage'}
    elif not c['reconstructionComplete'] or snapshot is None:
        result = {'state': 'unavailable'}
    else:
        snapshot_stage, snapshot_ledger = snapshot
        amount = sum(int(o['amount']) for o in snapshot_ledger.values() if get_key(o) == query)
        result = {'state': 'covered' if snapshot_stage <= 12 else 'filtered', 'amount': str(amount),
            'spendCoverage':'all_confirmed_spends' if snapshot_stage <= 12 else 'qualifying_version_1_txids_only',
            'mayIncludeSpentOutputs':snapshot_stage >= 13}
        if 'snapshotBlockId' in c:
            result.update(currentStage=current_stage, snapshotStage=snapshot_stage,
                          snapshotKind='current' if snapshot_id == c['acceptedBlocks'][-1]['blockId']
                          else 'historical')
        if 'ledgerView' in c:
            result['ledgerView'] = ledger_view
            if ledger_view == 'enhanced' and snapshot_stage >= 13:
                result['spendCoverage'] = 'qualifying_version_1_txids_plus_declared_extra_spends'
    assert result == c['expected'], (c['id'], result, c['expected'])
    if 'expectedActualUnspentAmount' in c:
        actual_amount = sum(int(o['amount']) for o in outputs.values() if get_key(o) == query)
        assert str(actual_amount) == c['expectedActualUnspentAmount'], (c['id'], actual_amount)
totals['accepted_chain_balance_traces'] = len(vectors['balanceTraceCases'])

for c in vectors['recoveryRetentionCases']:
    recommended = not c['retirementAnchorIsAcceptedAncestor'] or c['acceptedTipHeight'] - c['retirementHeight'] < 100
    mandatory = not c['retirementAnchorIsAcceptedAncestor'] or c['requiredByActiveState'] or c['recoveryInProgress']
    assert recommended == c['expectedRecommendedHold'], c
    assert mandatory == c['expectedMandatoryProtection'], c
totals['recovery_retention_boundary_cases'] = len(vectors['recoveryRetentionCases'])
for c in vectors['retentionDeviationCases']:
    assert (c['configuredMinimumBlocks'] >= 100) == c['expectedMinimumRecommendationMet']
    assert c['riskDisclosurePublished'] == c['expectedDisclosureRequirementMet']
totals['retention_policy_disclosure_cases'] = len(vectors['retentionDeviationCases'])

links = re.findall(r'\]\(([^)]+)\)', spec)
local_links = [x for x in links if not re.match(r'https?://', x)]
for link in local_links:
    assert (ROOT / 'opinions' / link.split('#')[0]).exists(), link
totals['local_links'] = len(local_links)
for index in ['README.md', 'opinions/README.md', 'SUMMARY.md']:
    assert (ROOT / index).read_text().count('0234.md') == 1, index
report = {'result': 'passed', 'checks': totals,
          'scope': 'Mathematical and decoded-profile fixture audit; not a deployed indexer or consensus implementation test.'}
print(json.dumps(report, indent=2))
