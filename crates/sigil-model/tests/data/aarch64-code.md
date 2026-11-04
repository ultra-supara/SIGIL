# SIGIL session

| Run |  |
|---|---|
| Tool | sigil 0\.0\.0\-example |
| Mode | static |
| Audit scope | binary\, binary\_code |
| Required checks | binary\.code\, binary\.container\, binary\.identity |
| Root | binary\-1 \/examples\/aarch64\-call\.o |
| Root | binary\-2 \/examples\/aarch64\-partial\.o |
| Observed | 2026\-10\-07T07\:00\:00Z to 2026\-10\-07T07\:00\:02Z |
| Policy time | 2026\-10\-07T07\:00\:00Z |

## Outcome

**Verdict:** FAIL · **Completeness:** INCOMPLETE

Confirmed\: 0 fail\, 0 warn\, 1 policy violations\.

- Required check not closed\: binary\.code
- Open question counted as a gap\: capability\:posix\.network\@sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0

## Findings

None.

## Open questions

| Open question | Rule | Treatment | Subject | Why |
|---|---|---|---|---|
| capability\:posix\.network\@sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0 | binary\.capability\_call | count as gap | sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0 | calls\:posix\.network\: binary\.code did not close |

## Policy violations

| Policy rule | Action | Subject | Evidence |
|---|---|---|---|
| policy\:capabilities\.deny\.posix\.network | fail | sha256\:2222222222222222222222222222222222222222222222222222222222222222\#aarch64\@0 | cs\:0x4c |

## Coverage

Entries\: 8\. Not closing their check\: 2\.

| Check | Scope | State |
|---|---|---|
| binary\.code | inst\:binary\-2\/aarch64\-partial\.o | partial\: code\: incomplete slice sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0 |
| binary\.code | sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0 | partial\: code\: no usable FDE bounds |

## Binaries

| Path | SHA\-256 | Size | Type | Container facts | Signature scan | Code |
|---|---|---|---|---|---|---|
| \/examples\/aarch64\-call\.o | 2222222222222222222222222222222222222222222222222222222222222222 | 1248 | ELF Rel aarch64 | complete | complete | complete |
| \/examples\/aarch64\-partial\.o | 2323232323232323232323232323232323232323232323232323232323232323 | 1248 | ELF Rel aarch64 | complete | complete | partial\: code\: incomplete slice sha256\:2323232323232323232323232323232323232323232323232323232323232323\#aarch64\@0 |

Facts of \/examples\/aarch64\-call\.o\:

| Fact | Value |
|---|---|
| Interpreter | \- |
| SONAME | \- |
| NEEDED | \- |
| RPATH | \- |
| RUNPATH | \- |
| Build\-id | \- |
| Comment | \- |
| Stripped | no |
| Exports | 1 |
| Undefined symbols \(link time\) | 1 |
| Data symbols | \- |
| Component | \- |
| Identity | \- |
| Versions | \- |

Undefined symbols \(link time\) of \/examples\/aarch64\-call\.o \(1\)\:

connect

No signature found\.

Capabilities of \/examples\/aarch64\-call\.o\:

| Capability | Import | Direct call sites |
|---|---|---|
| posix\.network | connect | 1\: connect\_zero\<script\>\\u\{001B\} \@ 0x4c\: connect\(x0\=0\, x1\=0\, x2\=0\) |

binary\.code\: complete\; 78 of 268435456 code bytes read\.

Facts of \/examples\/aarch64\-partial\.o\:

| Fact | Value |
|---|---|
| Interpreter | \- |
| SONAME | \- |
| NEEDED | \- |
| RPATH | \- |
| RUNPATH | \- |
| Build\-id | \- |
| Comment | \- |
| Stripped | no |
| Exports | 1 |
| Undefined symbols \(link time\) | 1 |
| Data symbols | \- |
| Component | \- |
| Identity | \- |
| Versions | \- |

Undefined symbols \(link time\) of \/examples\/aarch64\-partial\.o \(1\)\:

connect

No signature found\.

Capabilities of \/examples\/aarch64\-partial\.o\:

| Capability | Import | Direct call sites |
|---|---|---|
| posix\.network | connect | none found in the code searched\; binary\.code is partial \(see Coverage\) |

binary\.code\: partial \(1 gap\)\; 0 of 268435456 code bytes read\. Each gap is listed under Coverage\.

Container facts and direct call sites\. For an executable or a shared object\, imports are the names it asks its loader for\; for a relocatable object \(\.o\)\, they are the symbols left for the linker\. An import alone does not show that the code calls it\; the call sites above are the direct calls found in the code\.

Direct call sites only\. A call through a function pointer\, a function linked statically into the file\, and a raw system call are not found\, and references from data are not followed\. Only executable sections and the ranges of FDEs in \.eh\_frame are searched\, and only code with an FDE is analyzed\. In a relocatable object \(\.o\)\, addresses are file offsets\.

## Listeners

None.

## Processes

None.

## Other facts

artifacts\: 2\; file instances\: 2\; process values\: 0\; component claims\: 0\; release claims\: 0\; feature hints\: 2\; code facts\: 1\; relations\: 0\; rule support\: 0\; binding premises\: 0\; load facts\: 0\; write access\: 0\; assumptions\: 0

The session JSON holds every fact\; this report shows the outcome and what it rests on\.
