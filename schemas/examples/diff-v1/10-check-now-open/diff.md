# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:7446ed112019a82fcfb8a4006b68b1576a921157e3963ae38d3f0a56ce7dc694 | sha256\:47e9a1b094d3c967985a2adc3eb504c0fe37ac99795b4b9f2af7d091cc8cec35 |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | observe | observe |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) |
| Completeness | COMPLETE | INCOMPLETE |

Result\: WARN \+ INCOMPLETE \(the current session is incomplete\)\, under the policy default sigil\-policy\/1 \(sha256\:61e8b696227d8ba53d1f6b3208b1fde088806ee4be0f497eccceede5d5a42123\)\.

2 changes\, 0 not comparable\.

## Outcome

| Action | What | Baseline | Current |
|---|---|---|---|
| ignored | completeness | COMPLETE | INCOMPLETE |

## Coverage

| Action | Change | Check | Baseline | Current |
|---|---|---|---|---|
| WARN | opened | model\_store\.license | Complete 1 \(required\) | Partial 1 \(required\) |

Only open/closed transitions are reported. A check open on both sides whose states or gaps changed is not.

