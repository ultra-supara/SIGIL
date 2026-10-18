//! Code facts as the reports show them (PR-5a-2 spec §3.1, §3.3): argument values, call sites,
//! the cells of a content's Capabilities table, and the line of its input's `binary.code` entry.
//!
//! Pure functions. Every piece of input-derived text stays an input piece of a [`Shown`], so it
//! is escaped as the rest of the report is; this module adds only its own punctuation.

use crate::code::{ArgValue, CallKind, CallSite, CallTarget, CodeFacts, Reg, ValueUnknown};
use crate::coverage::{Coverage, CoverageState};
use crate::id::FnId;
use crate::text::UntrustedText;

use super::{coverage_state, Shown};

/// How many call sites a Capabilities cell shows. The session JSON keeps every one.
pub const CALL_SITES_SHOWN: usize = 5;

/// How many characters of a string constant a value shows.
pub const STRING_SHOWN: usize = 64;

/// A Capabilities cell of an inspection without code analysis.
pub const NOT_ANALYZED: &str = "not analyzed (use --code)";

/// A Capabilities cell with code analysis, the input's code searched, and no direct call site of
/// the import.
pub const NONE_FOUND: &str = "none found (see binary.code)";

/// A Capabilities cell of an inspection with code analysis whose input's code was not searched:
/// its `binary.code` entry is neither complete nor partial (unsupported, over a budget, …), or
/// it has none (plan P-p).
pub const NOT_SEARCHED: &str = "not analyzed (see binary.code)";

/// What an ELF content without a capability import gets instead of its Capabilities table.
pub const NO_CAPABILITY_IMPORTS: &str = "No capability imports.";

/// What an ELF content gets instead of [`NO_CAPABILITY_IMPORTS`] when its import list was cut
/// short at `binary_imports` (plan P-r): none of the `kept` imports is a capability import, and
/// those past the cut are not known.
pub fn no_capability_imports_kept(kept: usize) -> String {
    let imports = if kept == 1 { "import" } else { "imports" };
    format!("No capability imports among the {kept} {imports} kept (binary_imports; see Coverage).")
}

/// The line under a Capabilities table whose content's import list was cut short at
/// `binary_imports` (plan P-r).
pub const IMPORTS_CUT_SHORT: &str =
    "The import list was cut short at binary_imports; capability imports past it are not shown.";

/// What the install's Capabilities (imports) cell adds, after its keys or `-`, when the import
/// list was cut short at `binary_imports` (plan P-r).
pub const IMPORTS_CUT_SHORT_NOTE: &str = " (imports cut short)";

/// A Capabilities cell: [`NOT_ANALYZED`] when the inspection did not analyze code;
/// [`NOT_SEARCHED`] when it did, but the input's `binary.code` entry (`code`) does not say its
/// code was searched; else [`call_sites_cell`].
pub fn capability_cell(
    analyzed: bool,
    code: Option<&Coverage>,
    facts: Option<&CodeFacts>,
    import: &UntrustedText,
) -> Shown {
    if !analyzed {
        return Shown::own(NOT_ANALYZED);
    }
    if !searched(code) {
        return Shown::own(NOT_SEARCHED);
    }
    call_sites_cell(facts, import)
}

/// Whether an input's `binary.code` entry says its code was searched: complete or partial.
fn searched(code: Option<&Coverage>) -> bool {
    code.is_some_and(|c| {
        matches!(
            c.state,
            CoverageState::Complete | CoverageState::Partial { .. }
        )
    })
}

/// The direct call sites of `import` in a slice's `facts`: those whose target is that import, in
/// (address, id) order. A call that only feeds a value, to another import or to a function of the
/// slice, is not one.
pub fn calls_of<'f>(facts: Option<&'f CodeFacts>, import: &UntrustedText) -> Vec<&'f CallSite> {
    let mut calls: Vec<&CallSite> = facts
        .into_iter()
        .flat_map(|f| &f.call_sites)
        .filter(|c| matches!(&c.target, CallTarget::Import { symbol, .. } if symbol == import))
        .collect();
    calls.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.id.cmp(&b.id)));
    calls
}

/// A Capabilities cell of searched code: [`NONE_FOUND`], or the number of direct call sites,
/// then the first [`CALL_SITES_SHOWN`] of them joined by `; `, then how many more the session
/// JSON holds.
pub fn call_sites_cell(facts: Option<&CodeFacts>, import: &UntrustedText) -> Shown {
    let calls = calls_of(facts, import);
    let Some(f) = facts.filter(|_| !calls.is_empty()) else {
        return Shown::own(NONE_FOUND);
    };
    let mut shown = Shown::own(format!("{}: ", calls.len()));
    for (k, c) in calls.iter().take(CALL_SITES_SHOWN).enumerate() {
        if k > 0 {
            shown = shown.and("; ");
        }
        shown = shown.and_shown(call_site(c, f));
    }
    if calls.len() > CALL_SITES_SHOWN {
        shown = shown.and(format!(
            "; … and {} more (session JSON)",
            calls.len() - CALL_SITES_SHOWN
        ));
    }
    shown
}

/// One call site: `<function> @ 0x<addr>: <callee>(<reg>=<value>, …)`, and ` (tail jump)` after
/// a tail jump.
pub fn call_site(c: &CallSite, facts: &CodeFacts) -> Shown {
    let mut shown = function(facts, &c.caller)
        .and(format!(" @ {:#x}: ", c.addr))
        .and_shown(callee(&c.target))
        .and("(");
    for (k, a) in c.args.iter().enumerate() {
        if k > 0 {
            shown = shown.and(", ");
        }
        shown = shown.and_shown(argument(a, facts));
    }
    shown = shown.and(")");
    if c.kind == CallKind::TailJump {
        shown = shown.and(" (tail jump)");
    }
    shown
}

/// A function: its first name, else `fn@0x<entry>`. A caller the facts do not list is shown by
/// its ID.
pub fn function(facts: &CodeFacts, id: &FnId) -> Shown {
    match facts.functions.iter().find(|f| f.id == *id) {
        Some(f) => match f.names.first() {
            Some(name) => Shown::input(name),
            None => Shown::own(format!("fn@{:#x}", f.entry)),
        },
        None => Shown::own(id.as_str()),
    }
}

/// What a call reaches: an import's or an own export's symbol, a function of the slice by its
/// export name or `fn@0x<entry>`, or `indirect`.
pub fn callee(t: &CallTarget) -> Shown {
    match t {
        CallTarget::Import { symbol, .. } | CallTarget::OwnExportViaPlt { symbol, .. } => {
            Shown::input(symbol)
        }
        CallTarget::Internal { entry, export_name } => match export_name {
            Some(name) => Shown::input(name),
            None => Shown::own(format!("fn@{entry:#x}")),
        },
        CallTarget::Indirect { .. } => Shown::own("indirect"),
    }
}

/// A recorded argument: `<reg>=<value>`.
pub fn argument(v: &ArgValue, facts: &CodeFacts) -> Shown {
    Shown::own(format!("{}=", reg(register(v)))).and_shown(value(v, facts))
}

/// A value without its register (spec §3.3). A `ReturnOf` names a call site of the same slice's
/// `facts`.
pub fn value(v: &ArgValue, facts: &CodeFacts) -> Shown {
    match v {
        ArgValue::ConstInt { value, .. } => Shown::own(int(*value)),
        ArgValue::ConstStr { value, .. } => string(value),
        ArgValue::ReturnOf { call, .. } => match facts.call_sites.iter().find(|c| c.id == *call) {
            Some(c) => Shown::own("ret(")
                .and_shown(callee(&c.target))
                .and(format!("@{:#x})", c.addr)),
            None => Shown::own("ret(?)"),
        },
        ArgValue::Param { index, .. } => Shown::own(format!("param {index}")),
        ArgValue::Load {
            base,
            offset,
            width,
            ..
        } => Shown::own("load(")
            .and_shown(value(base, facts))
            .and(format!("{}, u{width})", signed_hex(*offset))),
        ArgValue::Low {
            value: inner, bits, ..
        } => Shown::own(format!("low{bits}("))
            .and_shown(value(inner, facts))
            .and(")"),
        ArgValue::Set { members, .. } => {
            let mut shown = Shown::own("{");
            for (k, m) in members.iter().enumerate() {
                if k > 0 {
                    shown = shown.and(" | ");
                }
                shown = shown.and_shown(value(m, facts));
            }
            shown.and("}")
        }
        ArgValue::Unknown { reason, .. } => Shown::own(match reason {
            ValueUnknown::ClobberedByCall => "?(clobbered)",
            ValueUnknown::MergedDisagreeing => "?(merged)",
            ValueUnknown::FromMemory => "?(memory)",
            ValueUnknown::NotModeled => "?(not modeled)",
        }),
    }
}

/// The line under a content's capabilities, from its input's `binary.code` entry: the state,
/// and for analyzed code the bytes read.
pub fn coverage_line(c: Option<&Coverage>) -> Shown {
    let Some(c) = c else {
        return Shown::own("binary.code: no coverage entry.");
    };
    match (&c.state, &c.budget) {
        (CoverageState::Complete, Some(b)) => Shown::own(format!(
            "binary.code: complete; {} of {} code bytes read.",
            b.used, b.limit
        )),
        (CoverageState::Partial { missing }, Some(b)) => Shown::own(format!(
            "binary.code: partial ({}); {} of {} code bytes read. Each gap is listed under Coverage.",
            partial_gaps(missing.len()),
            b.used,
            b.limit
        )),
        (CoverageState::Unsupported { what }, _) => {
            Shown::own(format!("binary.code: unsupported ({what})."))
        }
        // Complete or Partial without a budget is never reached by a valid session: C3 requires
        // the budget, and the viewer validates a session before rendering it.
        (state, _) => Shown::own("binary.code: ")
            .and_shown(coverage_state(state))
            .and("."),
    }
}

/// The gaps of a partial state, as the `binary.code` line and the terminal summary count them:
/// `1 gap`, `<n> gaps`.
pub fn partial_gaps(n: usize) -> String {
    if n == 1 {
        "1 gap".to_string()
    } else {
        format!("{n} gaps")
    }
}

/// An integer: decimal when `-65536 < v < 65536`, else hexadecimal, with `-` when negative.
fn int(v: i64) -> String {
    if (-65535..=65535).contains(&v) {
        v.to_string()
    } else if v < 0 {
        format!("-{:#x}", v.unsigned_abs())
    } else {
        format!("{v:#x}")
    }
}

/// A load's offset: `+0x<off>`, or `-0x<off>` when negative.
fn signed_hex(off: i64) -> String {
    if off < 0 {
        format!("-{:#x}", off.unsigned_abs())
    } else {
        format!("+{off:#x}")
    }
}

/// A string constant in quotes, cut at [`STRING_SHOWN`] characters with `…` (plan P-b). A value
/// that is not UTF-8 is cut in its shown form, `hex:<digits>`.
fn string(text: &UntrustedText) -> Shown {
    let (head, cut) = match text.as_str() {
        Some(s) => match s.char_indices().nth(STRING_SHOWN) {
            // `i` is where a character starts, so the slice ends on a boundary.
            Some((i, _)) => (UntrustedText::new(&s[..i]), true),
            None => (text.clone(), false),
        },
        None => {
            // `hex:` and two digits per byte: only the bytes shown are formatted.
            let n = (STRING_SHOWN - "hex:".len()) / 2;
            let bytes = text.as_bytes();
            let digits: String = bytes.iter().take(n).map(|b| format!("{b:02x}")).collect();
            (UntrustedText::new(format!("hex:{digits}")), bytes.len() > n)
        }
    };
    let quoted = Shown::own("\"").and_input(&head);
    if cut {
        quoted.and("…\"")
    } else {
        quoted.and("\"")
    }
}

/// The register an argument was read from.
fn register(v: &ArgValue) -> Reg {
    match v {
        ArgValue::ConstStr { reg, .. }
        | ArgValue::ConstInt { reg, .. }
        | ArgValue::ReturnOf { reg, .. }
        | ArgValue::Param { reg, .. }
        | ArgValue::Load { reg, .. }
        | ArgValue::Low { reg, .. }
        | ArgValue::Set { reg, .. }
        | ArgValue::Unknown { reg, .. } => *reg,
    }
}

/// A register's name, as the session JSON writes it.
fn reg(r: Reg) -> &'static str {
    match r {
        Reg::Rax => "rax",
        Reg::Rbx => "rbx",
        Reg::Rcx => "rcx",
        Reg::Rdx => "rdx",
        Reg::Rsi => "rsi",
        Reg::Rdi => "rdi",
        Reg::Rbp => "rbp",
        Reg::Rsp => "rsp",
        Reg::R8 => "r8",
        Reg::R9 => "r9",
        Reg::R10 => "r10",
        Reg::R11 => "r11",
        Reg::R12 => "r12",
        Reg::R13 => "r13",
        Reg::R14 => "r14",
        Reg::R15 => "r15",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{BoundsSource, Function, ImportVia};
    use crate::coverage::BudgetUse;
    use crate::evidence::Ref;
    use crate::id::{CallId, CheckId, SliceId};

    const R: Reg = Reg::Rdi;

    fn t(text: &str) -> UntrustedText {
        UntrustedText::new(text)
    }

    fn import(name: &str) -> CallTarget {
        CallTarget::Import {
            symbol: t(name),
            via: ImportVia::Plt,
        }
    }

    /// A call in `kernel` at `addr`, with the ID `cs:<addr>`.
    fn call(addr: u64, target: CallTarget, args: Vec<ArgValue>) -> CallSite {
        CallSite {
            id: CallId::new(format!("cs:{addr:#x}")).unwrap(),
            caller: FnId::new("fn:0x40").unwrap(),
            addr,
            kind: CallKind::Call,
            target,
            args,
        }
    }

    /// One slice's facts: the function `kernel` at 0x40, and `sites`.
    fn facts(sites: Vec<CallSite>) -> CodeFacts {
        CodeFacts {
            slice: SliceId::new(format!("sha256:{}#x86_64@0", "a".repeat(64))).unwrap(),
            functions: vec![Function {
                id: FnId::new("fn:0x40").unwrap(),
                entry: 0x40,
                end: 0x400,
                bounds: BoundsSource::EhFrameFde,
                names: vec![t("kernel")],
            }],
            call_sites: sites,
            predicate_checks: vec![],
            close_checks: vec![],
            guard_regions: vec![],
            param_mappings: vec![],
        }
    }

    fn c_int(reg: Reg, value: i64) -> ArgValue {
        ArgValue::ConstInt { reg, value }
    }

    fn c_param(reg: Reg, index: u8) -> ArgValue {
        ArgValue::Param { reg, index }
    }

    fn c_ret(reg: Reg, id: &str) -> ArgValue {
        ArgValue::ReturnOf {
            reg,
            call: CallId::new(id).unwrap(),
        }
    }

    fn c_str(text: UntrustedText) -> ArgValue {
        ArgValue::ConstStr {
            reg: R,
            addr: 0x2000,
            value: text,
        }
    }

    fn c_load(base: ArgValue, offset: i64, width: u8) -> ArgValue {
        ArgValue::Load {
            reg: R,
            base: Box::new(base),
            offset,
            width,
            site: 0x50,
        }
    }

    fn c_low(value: ArgValue, bits: u8) -> ArgValue {
        ArgValue::Low {
            reg: R,
            value: Box::new(value),
            bits,
        }
    }

    fn c_set(members: Vec<ArgValue>) -> ArgValue {
        ArgValue::Set { reg: R, members }
    }

    fn c_unknown(reason: ValueUnknown) -> ArgValue {
        ArgValue::Unknown { reg: R, reason }
    }

    /// Call sites of every target kind, for `ReturnOf`.
    fn targets() -> CodeFacts {
        facts(vec![
            call(0x4d, import("connect"), vec![]),
            call(
                0x30,
                CallTarget::Internal {
                    entry: 0x1120,
                    export_name: Some(t("helper")),
                },
                vec![],
            ),
            call(
                0x38,
                CallTarget::Internal {
                    entry: 0x2000,
                    export_name: None,
                },
                vec![],
            ),
            call(
                0x3c,
                CallTarget::OwnExportViaPlt {
                    symbol: t("own"),
                    entry: 0x1120,
                },
                vec![],
            ),
            call(
                0x44,
                CallTarget::Indirect {
                    value: c_unknown(ValueUnknown::FromMemory),
                },
                vec![],
            ),
        ])
    }

    #[test]
    fn every_value_form_has_its_text() {
        let f = targets();
        let cases = [
            (c_int(R, 0), "0"),
            (c_int(R, 65535), "65535"),
            (c_int(R, -65535), "-65535"),
            (c_int(R, 65536), "0x10000"),
            (c_int(R, -65536), "-0x10000"),
            (c_int(R, i64::MAX), "0x7fffffffffffffff"),
            (c_int(R, i64::MIN), "-0x8000000000000000"),
            (c_str(t("ggml_backend_score")), "\"ggml_backend_score\""),
            (c_ret(R, "cs:0x4d"), "ret(connect@0x4d)"),
            (c_ret(R, "cs:0x30"), "ret(helper@0x30)"),
            (c_ret(R, "cs:0x38"), "ret(fn@0x2000@0x38)"),
            (c_ret(R, "cs:0x3c"), "ret(own@0x3c)"),
            (c_ret(R, "cs:0x44"), "ret(indirect@0x44)"),
            (c_ret(R, "cs:0x999"), "ret(?)"),
            (c_param(R, 2), "param 2"),
            (c_load(c_param(R, 0), 8, 64), "load(param 0+0x8, u64)"),
            (c_load(c_param(R, 0), -16, 32), "load(param 0-0x10, u32)"),
            (c_load(c_param(R, 0), 0, 8), "load(param 0+0x0, u8)"),
            (c_low(c_ret(R, "cs:0x30"), 32), "low32(ret(helper@0x30))"),
            (
                c_set(vec![c_int(R, 1), c_int(R, 70000), c_param(R, 0)]),
                "{1 | 0x11170 | param 0}",
            ),
            (c_unknown(ValueUnknown::ClobberedByCall), "?(clobbered)"),
            (c_unknown(ValueUnknown::MergedDisagreeing), "?(merged)"),
            (c_unknown(ValueUnknown::FromMemory), "?(memory)"),
            (c_unknown(ValueUnknown::NotModeled), "?(not modeled)"),
        ];
        for (v, text) in cases {
            assert_eq!(value(&v, &f).terminal(), text, "{v:?}");
        }
    }

    #[test]
    fn nested_values_have_no_register() {
        let f = targets();
        let nested = c_load(c_load(c_param(Reg::Rbx, 0), 8, 64), 0x10, 32);
        assert_eq!(
            value(&nested, &f).terminal(),
            "load(load(param 0+0x8, u64)+0x10, u32)"
        );
        assert_eq!(
            argument(&nested, &f).terminal(),
            "rdi=load(load(param 0+0x8, u64)+0x10, u32)"
        );
        let set = ArgValue::Set {
            reg: Reg::Rsi,
            members: vec![c_ret(Reg::Rax, "cs:0x4d"), c_param(Reg::Rbx, 1)],
        };
        assert_eq!(
            argument(&set, &f).terminal(),
            "rsi={ret(connect@0x4d) | param 1}"
        );
        let low = ArgValue::Low {
            reg: Reg::Rdx,
            value: Box::new(c_param(Reg::Rcx, 3)),
            bits: 8,
        };
        assert_eq!(argument(&low, &f).terminal(), "rdx=low8(param 3)");
    }

    #[test]
    fn a_string_is_cut_at_64_characters() {
        let f = facts(vec![]);
        let shown = |text: UntrustedText| value(&c_str(text), &f).terminal();
        assert_eq!(shown(t(&"a".repeat(64))), format!("\"{}\"", "a".repeat(64)));
        assert_eq!(
            shown(t(&"a".repeat(70))),
            format!("\"{}…\"", "a".repeat(64))
        );
        // Characters, not bytes: 64 two-byte characters are not cut.
        assert_eq!(shown(t(&"é".repeat(64))), format!("\"{}\"", "é".repeat(64)));
        assert_eq!(
            shown(t(&"é".repeat(65))),
            format!("\"{}…\"", "é".repeat(64))
        );
        // Not UTF-8: its shown form, hex, is cut.
        assert_eq!(
            shown(UntrustedText::from_bytes(vec![0xff, 0x3c])),
            "\"hex:ff3c\""
        );
        assert_eq!(
            shown(UntrustedText::from_bytes(vec![0xff; 40])),
            format!("\"hex:{}…\"", "f".repeat(60))
        );
    }

    #[test]
    fn register_names_are_the_json_names() {
        use Reg::*;
        for r in [
            Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp, R8, R9, R10, R11, R12, R13, R14, R15,
        ] {
            assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(reg(r)));
        }
    }

    #[test]
    fn a_call_site_names_its_function_callee_and_arguments() {
        let site = call(
            0x4d,
            import("connect"),
            vec![c_int(Reg::Rdi, 0), c_param(Reg::Rsi, 1), c_int(Reg::Rdx, 0)],
        );
        let mut f = facts(vec![site.clone()]);
        assert_eq!(
            call_site(&site, &f).terminal(),
            "kernel @ 0x4d: connect(rdi=0, rsi=param 1, rdx=0)"
        );
        // The first of several names.
        f.functions[0].names = vec![t("a_first"), t("z_last")];
        assert_eq!(
            call_site(&site, &f).terminal(),
            "a_first @ 0x4d: connect(rdi=0, rsi=param 1, rdx=0)"
        );
        // No name: the entry.
        f.functions[0].names.clear();
        assert_eq!(
            call_site(&site, &f).terminal(),
            "fn@0x40 @ 0x4d: connect(rdi=0, rsi=param 1, rdx=0)"
        );
        // A caller the facts do not list: its ID.
        let mut lost = site.clone();
        lost.caller = FnId::new("fn:0x99").unwrap();
        assert_eq!(
            call_site(&lost, &f).terminal(),
            "fn:0x99 @ 0x4d: connect(rdi=0, rsi=param 1, rdx=0)"
        );
        // A tail jump to an import without arguments.
        let mut tail = call(0x60, import("fork"), vec![]);
        tail.kind = CallKind::TailJump;
        assert_eq!(
            call_site(&tail, &f).terminal(),
            "fn@0x40 @ 0x60: fork() (tail jump)"
        );
    }

    fn connects(addrs: &[u64]) -> Vec<CallSite> {
        addrs
            .iter()
            .map(|&a| call(a, import("connect"), vec![c_int(Reg::Rdi, 0)]))
            .collect()
    }

    #[test]
    fn a_cell_counts_and_shows_five_call_sites_in_address_order() {
        // IDs sort as text (cs:0x100 before cs:0x20); the cell sorts by address.
        let mut sites = connects(&[0x100, 0x20, 0x90, 0x48, 0x30, 0x60, 0x70]);
        // Calls that only feed a value: to another import, and to a function of the slice.
        sites.push(call(0x10, import("getenv"), vec![]));
        sites.push(call(
            0x11,
            CallTarget::Internal {
                entry: 0x40,
                export_name: None,
            },
            vec![],
        ));
        // An own export of the same name, through the PLT, is not the import.
        sites.push(call(
            0x12,
            CallTarget::OwnExportViaPlt {
                symbol: t("connect"),
                entry: 0x40,
            },
            vec![],
        ));
        let f = facts(sites);
        assert_eq!(
            call_sites_cell(Some(&f), &t("connect")).terminal(),
            "7: kernel @ 0x20: connect(rdi=0); kernel @ 0x30: connect(rdi=0); \
             kernel @ 0x48: connect(rdi=0); kernel @ 0x60: connect(rdi=0); \
             kernel @ 0x70: connect(rdi=0); … and 2 more (session JSON)"
        );
        assert_eq!(calls_of(Some(&f), &t("getenv")).len(), 1);
    }

    #[test]
    fn five_call_sites_have_no_more() {
        let f = facts(connects(&[0x20, 0x30, 0x40, 0x50, 0x60]));
        assert_eq!(
            call_sites_cell(Some(&f), &t("connect")).terminal(),
            "5: kernel @ 0x20: connect(rdi=0); kernel @ 0x30: connect(rdi=0); \
             kernel @ 0x40: connect(rdi=0); kernel @ 0x50: connect(rdi=0); \
             kernel @ 0x60: connect(rdi=0)"
        );
    }

    #[test]
    fn call_sites_at_one_address_are_in_id_order() {
        let mut second = call(0x20, import("connect"), vec![]);
        second.id = CallId::new("cs:0x20b").unwrap();
        second.kind = CallKind::TailJump;
        let first = call(0x20, import("connect"), vec![]);
        let f = facts(vec![second, first]);
        assert_eq!(
            call_sites_cell(Some(&f), &t("connect")).terminal(),
            "2: kernel @ 0x20: connect(); kernel @ 0x20: connect() (tail jump)"
        );
    }

    #[test]
    fn no_direct_call_site_is_none_found() {
        assert_eq!(call_sites_cell(None, &t("connect")).terminal(), NONE_FOUND);
        let f = facts(vec![call(0x20, import("getenv"), vec![])]);
        assert_eq!(
            call_sites_cell(Some(&f), &t("connect")).terminal(),
            NONE_FOUND
        );
    }

    #[test]
    fn a_cell_without_code_is_not_analyzed() {
        let f = facts(connects(&[0x20]));
        let done = entry(CoverageState::Complete, Some((78, 1 << 28)));
        assert_eq!(
            capability_cell(false, Some(&done), Some(&f), &t("connect")).terminal(),
            NOT_ANALYZED
        );
        assert_eq!(
            capability_cell(true, Some(&done), Some(&f), &t("connect")).terminal(),
            "1: kernel @ 0x20: connect(rdi=0)"
        );
    }

    /// Plan P-p: "none found" only where the input's code was searched (its `binary.code` entry
    /// is complete or partial); otherwise the cell says the code was not analyzed.
    #[test]
    fn a_cell_of_code_not_searched_is_not_analyzed() {
        let other = facts(vec![call(0x20, import("getenv"), vec![])]);
        let partial = CoverageState::Partial {
            missing: vec!["code: a gap".to_string()],
        };
        for state in [CoverageState::Complete, partial] {
            let c = entry(state, Some((78, 1 << 28)));
            for f in [Some(&other), None] {
                assert_eq!(
                    capability_cell(true, Some(&c), f, &t("connect")).terminal(),
                    NONE_FOUND,
                    "{c:?}"
                );
            }
        }
        // Any other state, or no entry: not searched, whatever the facts hold.
        let f = facts(connects(&[0x20]));
        let not_searched = [
            Some(entry(
                CoverageState::Unsupported {
                    what: crate::binary_input::CODE_UNSUPPORTED.to_string(),
                },
                None,
            )),
            Some(entry(
                CoverageState::BudgetExceeded {
                    budget: "binary_bytes".to_string(),
                    used: 2,
                    limit: 1,
                },
                None,
            )),
            Some(entry(
                CoverageState::Error {
                    message: t("read failed"),
                },
                None,
            )),
            None,
        ];
        for c in &not_searched {
            assert_eq!(
                capability_cell(true, c.as_ref(), Some(&f), &t("connect")).terminal(),
                NOT_SEARCHED,
                "{c:?}"
            );
            assert_eq!(
                capability_cell(false, c.as_ref(), Some(&f), &t("connect")).terminal(),
                NOT_ANALYZED,
                "{c:?}"
            );
        }
        assert_eq!(NOT_SEARCHED, "not analyzed (see binary.code)");
    }

    fn entry(state: CoverageState, budget: Option<(u64, u64)>) -> Coverage {
        Coverage {
            check: CheckId::new("binary.code").unwrap(),
            scope: Ref::Audit,
            state,
            budget: budget.map(|(used, limit)| BudgetUse {
                budget: "binary_code_bytes".to_string(),
                used,
                limit,
            }),
        }
    }

    #[test]
    fn the_coverage_line_of_each_state() {
        let line = |c: Option<&Coverage>| coverage_line(c).terminal();
        let partial = |n: usize| CoverageState::Partial {
            missing: (0..n).map(|k| format!("gap {k}")).collect(),
        };
        assert_eq!(
            line(Some(&entry(CoverageState::Complete, Some((78, 268435456))))),
            "binary.code: complete; 78 of 268435456 code bytes read."
        );
        assert_eq!(
            line(Some(&entry(partial(1), Some((1, 1))))),
            "binary.code: partial (1 gap); 1 of 1 code bytes read. Each gap is listed under Coverage."
        );
        assert_eq!(
            line(Some(&entry(partial(3), Some((10, 20))))),
            "binary.code: partial (3 gaps); 10 of 20 code bytes read. Each gap is listed under Coverage."
        );
        assert_eq!(
            line(Some(&entry(
                CoverageState::Unsupported {
                    what: "code analysis: x86-64 ELF64 little-endian only".to_string()
                },
                None
            ))),
            "binary.code: unsupported (code analysis: x86-64 ELF64 little-endian only)."
        );
        assert_eq!(
            line(Some(&entry(
                CoverageState::BudgetExceeded {
                    budget: "binary_bytes".to_string(),
                    used: 10,
                    limit: 5
                },
                None
            ))),
            "binary.code: budget exceeded: binary_bytes (10 of 5)."
        );
        assert_eq!(line(None), "binary.code: no coverage entry.");
    }

    #[test]
    fn input_text_is_escaped_in_markdown() {
        let hostile = "a|b`c*d\ne";
        let mut f = facts(vec![call(0x4d, import(hostile), vec![c_str(t(hostile))])]);
        f.functions[0].names = vec![t(hostile)];
        let md = call_sites_cell(Some(&f), &t(hostile)).markdown();
        let plain = format!("1: {hostile} @ 0x4d: {hostile}(rdi=\"{hostile}\")");
        assert_eq!(md, t(&plain).markdown_inline());
        assert!(!md.contains('\n'), "{md}");
        for c in ['|', '`', '*'] {
            let bare = md
                .char_indices()
                .filter(|(i, x)| *x == c && !md[..*i].ends_with('\\'))
                .count();
            assert_eq!(bare, 0, "{c} in {md}");
        }
    }
}
