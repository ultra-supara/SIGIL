# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:7446ed112019a82fcfb8a4006b68b1576a921157e3963ae38d3f0a56ce7dc694 | sha256\:e5fedab833aa0344831b21acd8387e515f1f3d2c3df2beff0e6065a04bdd8de7 |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | observe | observe |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) |

4 changes\, 0 not comparable\.

## Outcome

| What | Baseline | Current |
|---|---|---|
| verdict | PASS | WARN |
| completeness | COMPLETE | INCOMPLETE |

## Coverage

| Change | Check | Baseline | Current |
|---|---|---|---|
| opened | model\_store\.integrity | Complete 1 \(required\) | Partial 1 \(required\) |

Only open/closed transitions are reported. A check open on both sides whose states or gaps changed is not.

## Findings

| Change | Rule | Subject | Findings |
|---|---|---|---|
| new | model\.blob\_missing | model\:models\/registry\.ollama\.ai\/library\/m\/latest\#1 | finding\:model\.blob\_missing\@model\:models\/registry\.ollama\.ai\/library\/m\/latest\#1 |

