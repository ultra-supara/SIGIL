# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:7446ed112019a82fcfb8a4006b68b1576a921157e3963ae38d3f0a56ce7dc694 | sha256\:7a644e85c5a5a3243db3bc6e63426f2929f0855074bc3ab9cccf2182f53a822a |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | observe | observe |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) |
| Completeness | COMPLETE | COMPLETE |

Result\: FAIL \+ COMPLETE\, under the policy default sigil\-policy\/1 \(sha256\:61e8b696227d8ba53d1f6b3208b1fde088806ee4be0f497eccceede5d5a42123\)\.

3 changes\, 0 not comparable\.

## Outcome

| Action | What | Baseline | Current |
|---|---|---|---|
| ignored | verdict | PASS | WARN |

## Findings

| Action | Change | Rule | Subject | Findings |
|---|---|---|---|---|
| WARN \(as decided\) | new | exposure\.bind\_public | port 11434 | finding\:exposure\.bind\_public\@listener\:tcp\/0\.0\.0\.0\:11434\#7002 |

## Listeners

| Action | Change | Port | Baseline | Current |
|---|---|---|---|---|
| FAIL | bind widened | 11434 | loopback | wildcard |

