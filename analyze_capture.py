import json
from collections import defaultdict
from datetime import datetime

with open(r'c:\Users\ARB\Desktop\capture2.json', 'r') as f:
    packets = json.load(f)

print(f'Total packets in capture: {len(packets)}')

queries = []
responses = []
non_dns = 0

for pkt in packets:
    layers = pkt.get('_source', {}).get('layers', {})
    dns = layers.get('dns')
    if not dns:
        non_dns += 1
        continue

    flags_tree = dns.get('dns.flags_tree', {})
    qr = flags_tree.get('dns.flags.response', '0')

    frame = layers.get('frame', {})
    ip_layer = layers.get('ip', {})

    info = {
        'frame_time': frame.get('frame.time', ''),
        'frame_number': frame.get('frame.number', ''),
        'ip_src': ip_layer.get('ip.src', ''),
        'ip_dst': ip_layer.get('ip.dst', ''),
        'rcode': flags_tree.get('dns.flags.rcode', 'N/A'),
        'truncated': flags_tree.get('dns.flags.truncated', '0'),
        'answer_count': dns.get('dns.count.answers', '0'),
        'has_answers_section': 'Answers' in dns,
        'query_name': '',
    }

    queries_section = dns.get('Queries', {})
    for key in queries_section:
        qry = queries_section[key]
        info['query_name'] = qry.get('dns.qry.name', '')
        break

    if qr == '1':
        responses.append(info)
    else:
        queries.append(info)

print(f'DNS Queries (QR=0): {len(queries)}')
print(f'DNS Responses (QR=1): {len(responses)}')
print(f'Non-DNS packets: {non_dns}')

# ========== SECTION 1 & 2 ==========
print('\n' + '=' * 80)
print('SECTION 1 & 2: DNS RESPONSES GROUPED BY SOURCE IP')
print('=' * 80)

resp_by_ip = defaultdict(list)
for r in responses:
    resp_by_ip[r['ip_src']].append(r)

header = f"{'Source IP':<22} {'Total':<8} {'RCODE=0':<10} {'RCODE=2':<10} {'RC0+Answers':<14} {'Truncated':<10} {'Other RCODE':<15}"
print(f'\n{header}')
print('-' * len(header))

for ip in sorted(resp_by_ip.keys()):
    resps = resp_by_ip[ip]
    total = len(resps)
    rcode0 = sum(1 for r in resps if r['rcode'] == '0')
    rcode2 = sum(1 for r in resps if r['rcode'] == '2')
    rcode0_with_answers = sum(1 for r in resps if r['rcode'] == '0' and (int(r['answer_count']) > 0 or r['has_answers_section']))
    truncated_count = sum(1 for r in resps if r['truncated'] == '1')
    other_rcodes = defaultdict(int)
    for r in resps:
        if r['rcode'] not in ('0', '2'):
            other_rcodes[r['rcode']] += 1
    other_str = ', '.join(f'rc{k}:{v}' for k, v in sorted(other_rcodes.items())) if other_rcodes else '-'

    print(f'{ip:<22} {total:<8} {rcode0:<10} {rcode2:<10} {rcode0_with_answers:<14} {truncated_count:<10} {other_str:<15}')

# RCODE=0 but no answers
print('\n--- RCODE=0 responses WITHOUT answer data ---')
found_any = False
for ip in sorted(resp_by_ip.keys()):
    resps = resp_by_ip[ip]
    no_answer = [r for r in resps if r['rcode'] == '0' and int(r['answer_count']) == 0 and not r['has_answers_section']]
    if no_answer:
        found_any = True
        print(f'  {ip}: {len(no_answer)} responses with rcode=0 but NO answer data')
        for r in no_answer[:5]:
            print(f'    Frame {r["frame_number"]} at {r["frame_time"]}')
if not found_any:
    print('  None found - all RCODE=0 responses had answer data.')

# ========== SECTION 3 ==========
print('\n' + '=' * 80)
print('SECTION 3: DNS QUERIES GROUPED BY DESTINATION IP')
print('=' * 80)

queries_by_dst = defaultdict(int)
for q in queries:
    queries_by_dst[q['ip_dst']] += 1

print(f"\n{'Destination IP':<22} {'Query Count':<12}")
print('-' * 34)
for ip in sorted(queries_by_dst.keys(), key=lambda x: queries_by_dst[x], reverse=True):
    print(f'{ip:<22} {queries_by_dst[ip]:<12}')

# ========== SECTION 4 ==========
print('\n' + '=' * 80)
print('SECTION 4: TIMING ANALYSIS')
print('=' * 80)

all_times = []
for pkt in packets:
    layers = pkt.get('_source', {}).get('layers', {})
    frame = layers.get('frame', {})
    t = frame.get('frame.time', '')
    if t:
        try:
            t_clean = t.replace('Z', '+00:00')
            if '.' in t_clean:
                parts = t_clean.split('.')
                frac_and_tz = parts[1]
                for i, c in enumerate(frac_and_tz):
                    if c in ('+', '-') and i > 0:
                        frac = frac_and_tz[:i][:6]
                        tz = frac_and_tz[i:]
                        t_clean = parts[0] + '.' + frac + tz
                        break
            dt = datetime.fromisoformat(t_clean)
            all_times.append(dt)
        except Exception:
            pass

if all_times:
    all_times.sort()
    first = all_times[0]
    last = all_times[-1]
    duration = (last - first).total_seconds()

    print(f'\nFirst packet: {first.isoformat()}')
    print(f'Last packet:  {last.isoformat()}')
    print(f'Duration:     {duration:.3f} seconds ({duration / 60:.2f} minutes)')
    print(f'Total packets with timestamps: {len(all_times)}')

    # Gaps > 1 second
    print(f'\nGaps > 1 second between consecutive packets:')
    gaps = []
    for i in range(1, len(all_times)):
        gap = (all_times[i] - all_times[i - 1]).total_seconds()
        if gap > 1.0:
            gaps.append((i, gap, all_times[i - 1], all_times[i]))

    if gaps:
        print(f'  Found {len(gaps)} gaps > 1s:')
        for idx, (i, gap, t1, t2) in enumerate(gaps):
            print(f'  Gap #{idx + 1}: {gap:.3f}s  (between packet index {i - 1} and {i})')
            print(f'    From: {t1.isoformat()}')
            print(f'    To:   {t2.isoformat()}')
            if idx >= 19:
                remaining = len(gaps) - 20
                print(f'  ... and {remaining} more gaps')
                break
    else:
        print('  No gaps > 1 second found.')

    if duration > 0:
        print(f'\nAverage packet rate: {len(all_times) / duration:.1f} packets/sec')

# ========== SERVFAIL detail ==========
print('\n' + '=' * 80)
print('ADDITIONAL: SERVFAIL (RCODE=2) RESPONSE DETAILS')
print('=' * 80)

servfails = [r for r in responses if r['rcode'] == '2']
if servfails:
    print(f'\nTotal SERVFAIL responses: {len(servfails)}')
    for r in servfails[:15]:
        print(f'  Frame {r["frame_number"]}: from {r["ip_src"]} at {r["frame_time"]}  query={r["query_name"]}')
    if len(servfails) > 15:
        print(f'  ... and {len(servfails) - 15} more')
else:
    print('\nNo SERVFAIL responses found.')

# Truncated
trunc = [r for r in responses if r['truncated'] == '1']
if trunc:
    print(f'\nTruncated responses: {len(trunc)}')
    for r in trunc[:10]:
        print(f'  Frame {r["frame_number"]}: from {r["ip_src"]} rcode={r["rcode"]} answers={r["answer_count"]}')
else:
    print('\nNo truncated responses found.')

# ========== Per-IP timing ==========
print('\n' + '=' * 80)
print('ADDITIONAL: PER-IP RESPONSE TIMING')
print('=' * 80)

for ip in sorted(resp_by_ip.keys()):
    resps = resp_by_ip[ip]
    times_for_ip = []
    for r in resps:
        t = r['frame_time']
        if t:
            try:
                t_clean = t.replace('Z', '+00:00')
                if '.' in t_clean:
                    parts = t_clean.split('.')
                    frac_and_tz = parts[1]
                    for i, c in enumerate(frac_and_tz):
                        if c in ('+', '-') and i > 0:
                            frac = frac_and_tz[:i][:6]
                            tz = frac_and_tz[i:]
                            t_clean = parts[0] + '.' + frac + tz
                            break
                dt = datetime.fromisoformat(t_clean)
                times_for_ip.append(dt)
            except Exception:
                pass
    if times_for_ip:
        times_for_ip.sort()
        ip_first = times_for_ip[0]
        ip_last = times_for_ip[-1]
        ip_dur = (ip_last - ip_first).total_seconds()
        print(f'\n  {ip}:')
        print(f'    First response: {ip_first.isoformat()}')
        print(f'    Last response:  {ip_last.isoformat()}')
        print(f'    Span: {ip_dur:.3f}s  |  Count: {len(times_for_ip)}')
