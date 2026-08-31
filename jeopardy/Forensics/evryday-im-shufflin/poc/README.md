# evryday im shufflin

## Proof of Concept

```bash
tshark -r tr4ff.pcap -Y "ip.src == 10.42.42.10 && ip.dst == 10.42.42.20 && udp && data.len == 1" -T fields -e frame.time -e data.data | sort | awk -F'\t' '{print $2}' | sed '/^$/d' | tr -d '\n' | xxd -r -p
```

**FLAG:** `JCC{t1m3l1n3_d3t41l_r3c0n_ftw}`
