# SIGIL comparison

|  | Baseline | Current |
|---|---|---|
| Session | sha256\:dc32909f93bd8a3a9cbfcd99ddd54a086ea87ddf3c9a076ce2f5ef2aa43344ef | sha256\:3884712fc15215733043622e16cb33d23e1370829ac1b4e923a3a3b20f5e388b |
| Tool | sigil 0\.0\.0\-example | sigil 0\.0\.0\-example |
| Mode | static | static |
| Started | 2026\-10\-07T07\:00\:00Z | 2026\-10\-07T07\:00\:00Z |
| Policy | deny\-capabilities 1 \(sha256\:a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4\) | deny\-capabilities 1 \(sha256\:a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4\) |
| Completeness | COMPLETE | COMPLETE |

Result\: FAIL \+ COMPLETE\, under the policy default sigil\-policy\/1 \(sha256\:61e8b696227d8ba53d1f6b3208b1fde088806ee4be0f497eccceede5d5a42123\)\.

1 change\, 0 not comparable\.

## Open questions

| Action | Change | Rule | Subject | Open questions |
|---|---|---|---|---|
| FAIL \(as decided\) | new | binary\.capability\_call | x86\_64 slice at \/home\/user\/src\/suspicious\_kernel\-gcc\-O2\.ocapability\:posix\.process\_spawn\@ | capability\:posix\.process\_spawn\@sha256\:aa3b172e12f6a1e4a0661c2a286bb1eb86901d830bb6d26fa7b1630aef2e0f4a\#x86\_64\@0 |

