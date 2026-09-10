# Metrics

Measured on an Intel-class workstation, Python 3.13, fully offline, against the
committed fixture feeds. Updated after each feature; the table below is from the
`sentinai --demo` pipeline.

## Test suite

| metric | value |
|---|---|
| tests collected (`discover -s tests`) | 81 |
| pass / fail | 81 / 0 |
| runtime | ~6.1 s |
| external deps | none (stdlib only) |

## Pipeline accuracy on planted fixtures (detectors)

| detector | TP (planted) | FP (clean baseline) | precision on fixtures |
|---|---|---|---|
| ssh-brute (`ssh-brute`) | 1 (198.51.100.7, count=6 in window) | 0 | 1.00 |
| web-attack SQLi (`web_sqli`) | 2 | 0 | 1.00 |
| web-attack XSS (`web_xss`) | 1 | 0 | 1.00 |
| process-suspicious (`proc_suspicious`) | 2 (xmrig + kdevtmpfsi) | 0 | 1.00 |
| flow-beacon (`flow_beacon`) | 1 | 0 | 1.00 |
| flow-port-scan (`flow_scan`) | 1 | 0 | 1.00 |
| alert-feed promoted | 3 | 0 | 1.00 |

Clean baseline (192.0.2.11, 203.0.113.60 single/benign events) produced **zero**
findings — the planted brute force is flagged exactly, nothing else.

## Demo metrics (`sentinai --demo`)

| metric | value |
|---|---|
| exit code | 0 (offline proof) |
| incidents opened | 2 (INS-1 multi-channel actor 198.51.100.7; INS-2 alert+flow scanner 203.0.113.5) |
| incident #1 channels | 4 (auth + web + flow + alert) |
| kill-chain stages | 3 (Initial Access -> Execution -> Command and Control) |
| containment | CONTAINED (block-src auto-approve, RFC 5737 simulation recorded) |
| agent iterations / budget | 12 / 20 |
| time-to-contain (detection -> block, simulated) | ~440 s (~7.3 min) |
| findings attributed to incident #1 | 7 |
| response actions | block-src x1, disable-user x2, rotate-fixture-secret x1, snapshot-artifact x5 |
| IOC list entries | 6 |
| remediation checklist items | 9 |
| lessons learned | 7 |

## Watch mode (`sentinai watch --budget 30 --interval 1800`)

| metric | value |
|---|---|
| rounds consumed / budget | 30 (terminates) |
| incremental incident discoveries | actor 198.51.100.7 at round 3 |
| live incidents | 2 |