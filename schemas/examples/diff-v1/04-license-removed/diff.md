# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:7446ed112019a82fcfb8a4006b68b1576a921157e3963ae38d3f0a56ce7dc694 | sha256\:845d7dc364fb5e35100667fb8c5d3ee1fad171bc2001f11b43237951078fda86 |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | observe | observe |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) |

4 changes\, 0 not comparable\.

## Outcome

| What | Baseline | Current |
|---|---|---|
| verdict | PASS | WARN |

## Findings

| Change | Rule | Subject | Findings |
|---|---|---|---|
| new | model\.license\_missing | model\:models\/registry\.ollama\.ai\/library\/m\/latest | finding\:model\.license\_missing\@model\:models\/registry\.ollama\.ai\/library\/m\/latest |

## Models

| Change | Model | Baseline | Current |
|---|---|---|---|
| layer application\/vnd\.ollama\.image\.license \#0 | model\:models\/registry\.ollama\.ai\/library\/m\/latest | sha256\:1313131313131313131313131313131313131313131313131313131313131313 | absent |
| license | model\:models\/registry\.ollama\.ai\/library\/m\/latest | MIT | no license layer |

