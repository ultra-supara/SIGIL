# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:6f02e8e60f915894721e7b088ff9c589b7f476a12b3a843817f9aca8357144aa | sha256\:8552a00067a5de6060efd8fe5b6b82a7de5692a0013beb11ab0c8e5bc9b0cf03 |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | static | static |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) | default 1 \(sha256\:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3\) |
| Completeness | COMPLETE | COMPLETE |

Result\: WARN \+ COMPLETE\, under the policy default sigil\-policy\/1 \(sha256\:61e8b696227d8ba53d1f6b3208b1fde088806ee4be0f497eccceede5d5a42123\)\.

1 change\, 0 not comparable\.

## Installation

| Action | Change | Where | Baseline | Current |
|---|---|---|---|---|
| WARN | component ggml\-base \(x86\_64\) | inst\:lib\/ollama\/libggml\-base\.so\.0\.13\.1 | reference matched 0\.13\.1 | conflicting 0\.12\.0\, 0\.13\.1 |

