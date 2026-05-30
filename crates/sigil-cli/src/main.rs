use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
use sigil_core::aibom::{render_ai_bom, AiBom};
use sigil_core::assess::{
    capability_for_symbol, evaluate_policy, load_policy, PolicyViolation, Verdict,
};
use sigil_core::evidence::{
    CapabilityEvidence, Evidence, EvidenceItem, ExternalCall, UnsupportedInstruction,
};
use sigil_core::ir::Function;
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
use sigil_core::report::render_report;
use sigil_core::runtime::RuntimeListeners;
use sigil_core::safeisa::{emit_safeisa, render_safeisa, Program};
use sigil_core::x86::{decode_x86_64, lift_instructions, load_function};

#[derive(Debug, Parser)]
#[command(name = "sigil")]
#[command(about = "Local-first security assessment for AI-native binaries")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Lift {
        binary: PathBuf,
        #[arg(long)]
        entry: String,
        #[arg(long)]
        emit_ir: PathBuf,
        #[arg(long)]
        emit_safeisa: PathBuf,
    },
    Assess {
        binary: PathBuf,
        #[arg(long)]
        entry: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        emit_evidence: Option<PathBuf>,
        #[arg(long = "external-call")]
        external_call: Vec<String>,
    },
    Trace,
    PolicyFromSource,
    Explain,
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Aibom {
        #[command(subcommand)]
        command: AiBomCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    Inspect {
        #[command(subcommand)]
        target: RuntimeInspectTarget,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeInspectTarget {
    Ollama(OllamaArgs),
}

#[derive(Debug, Subcommand)]
enum AiBomCommand {
    Generate(AiBomGenerateArgs),
}

#[derive(Debug, Parser)]
struct OllamaArgs {
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    models_dir: Option<PathBuf>,
    #[arg(long = "no-probe-api", action = ArgAction::SetFalse, default_value_t = true)]
    probe_api: bool,
    #[arg(long = "no-inspect-runtime", action = ArgAction::SetFalse, default_value_t = true)]
    inspect_runtime: bool,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AiBomFormat {
    Json,
    Md,
}

#[derive(Debug, Parser)]
struct AiBomGenerateArgs {
    #[arg(long)]
    runtime: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    models_dir: Option<PathBuf>,
    #[arg(long = "no-probe-api", action = ArgAction::SetFalse, default_value_t = true)]
    probe_api: bool,
    #[arg(long = "no-inspect-runtime", action = ArgAction::SetFalse, default_value_t = true)]
    inspect_runtime: bool,
    #[arg(long, default_value = "json")]
    format: AiBomFormat,
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Lift {
            binary,
            entry,
            emit_ir,
            emit_safeisa,
        } => cmd_lift(binary, entry, emit_ir, emit_safeisa),
        Command::Assess {
            binary,
            entry,
            policy,
            out,
            emit_evidence,
            external_call,
        } => assess_external_calls(binary, entry, policy, out, emit_evidence, external_call),
        Command::Trace => placeholder("trace"),
        Command::PolicyFromSource => placeholder("policy-from-source"),
        Command::Explain => placeholder("explain"),
        Command::Runtime { command } => cmd_runtime(command),
        Command::Aibom { command } => cmd_aibom(command),
    }
}

fn placeholder(name: &str) -> Result<()> {
    println!("{name} is not implemented yet");
    Ok(())
}

fn assess_external_calls(
    binary: PathBuf,
    entry: String,
    policy_path: PathBuf,
    out: Option<PathBuf>,
    emit_evidence: Option<PathBuf>,
    external_calls: Vec<String>,
) -> Result<()> {
    let policy = load_policy(&policy_path)?;
    let mut capabilities = vec!["arithmetic".to_string()];
    let mut calls = Vec::new();
    let mut capability_evidence: BTreeMap<String, Vec<_>> = BTreeMap::new();

    for symbol in &external_calls {
        let capability = capability_for_symbol(symbol).map(str::to_string);
        if let Some(capability_name) = &capability {
            capabilities.push(capability_name.clone());
            capability_evidence
                .entry(capability_name.clone())
                .or_default();
        }
        calls.push(ExternalCall {
            symbol: symbol.clone(),
            capability,
            address: "unknown".to_string(),
        });
    }

    if external_calls.is_empty() {
        return assess_binary(binary, entry, policy_path, out, emit_evidence);
    }

    let result = evaluate_policy(&policy, capabilities.iter().map(String::as_str));
    let unique_capabilities: BTreeSet<String> = capabilities.into_iter().collect();
    let evidence = Evidence {
        binary: binary.display().to_string(),
        entry,
        verdict: result.verdict,
        capabilities: unique_capabilities
            .into_iter()
            .map(|name| CapabilityEvidence {
                evidence: capability_evidence.remove(&name).unwrap_or_default(),
                name,
            })
            .collect(),
        external_calls: calls,
        unsupported_instructions: vec![],
        policy_violations: result.violations,
    };

    if let Some(path) = emit_evidence {
        std::fs::write(path, evidence.to_json()?)?;
    }
    if let Some(path) = out {
        std::fs::write(path, render_report(&evidence, None))?;
    }
    println!("SIGIL Verdict: [{}]", verdict_text(evidence.verdict));
    Ok(())
}

fn verdict_text(verdict: Verdict) -> &'static str {
    verdict.as_str()
}

fn cmd_runtime(command: RuntimeCommand) -> Result<()> {
    match command {
        RuntimeCommand::Inspect { target } => match target {
            RuntimeInspectTarget::Ollama(args) => {
                let out = args.out.clone();
                let report = inspect_ollama(ollama_options(args))?;
                if let Some(path) = out {
                    ensure_parent_dir(&path)?;
                    std::fs::write(path, AiBom::from(&report).to_json()?)?;
                }
                println!("SIGIL Runtime Verdict: [{}]", report.verdict);
                Ok(())
            }
        },
    }
}

fn cmd_aibom(command: AiBomCommand) -> Result<()> {
    match command {
        AiBomCommand::Generate(args) => {
            if args.runtime != "ollama" {
                anyhow::bail!("unsupported AI-BOM runtime: {}", args.runtime);
            }
            let format = args.format;
            let out = args.out.clone();
            let options = OllamaInspectOptions {
                model: args.model,
                models_dir: args
                    .models_dir
                    .unwrap_or_else(OllamaInspectOptions::default_models_dir),
                host: resolve_host(args.host),
                probe_api: args.probe_api,
                runtime_listeners: resolve_runtime_listeners(args.inspect_runtime),
            };
            let report = inspect_ollama(options)?;
            let bom = AiBom::from(&report);
            let contents = match format {
                AiBomFormat::Json => bom.to_json()?,
                AiBomFormat::Md => render_ai_bom(&bom),
            };
            ensure_parent_dir(&out)?;
            std::fs::write(&out, contents)?;
            println!("SIGIL AI-BOM: {}", out.display());
            Ok(())
        }
    }
}

fn resolve_runtime_listeners(inspect_runtime: bool) -> RuntimeListeners {
    if inspect_runtime {
        RuntimeListeners::Inspect
    } else {
        RuntimeListeners::Disabled
    }
}

// Resolution order: explicit --host -> OLLAMA_HOST env -> loopback default.
// The flag has no clap default so an omitted --host can defer to OLLAMA_HOST.
fn resolve_host(flag: Option<String>) -> String {
    flag.or_else(|| {
        std::env::var("OLLAMA_HOST")
            .ok()
            .filter(|value| !value.is_empty())
    })
    .unwrap_or_else(|| "http://127.0.0.1:11434".to_string())
}

fn ollama_options(args: OllamaArgs) -> OllamaInspectOptions {
    OllamaInspectOptions {
        model: args.model,
        models_dir: args
            .models_dir
            .unwrap_or_else(OllamaInspectOptions::default_models_dir),
        host: resolve_host(args.host),
        probe_api: args.probe_api,
        runtime_listeners: resolve_runtime_listeners(args.inspect_runtime),
    }
}

fn ensure_parent_dir(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn cmd_lift(
    binary: PathBuf,
    entry: String,
    emit_ir: PathBuf,
    emit_safeisa_path: PathBuf,
) -> Result<()> {
    let (ir, safeisa) = analyze_binary(&binary, &entry)?;
    std::fs::write(emit_ir, render_ir(&ir))?;
    std::fs::write(emit_safeisa_path, render_safeisa(&safeisa, &entry))?;
    Ok(())
}

fn assess_binary(
    binary: PathBuf,
    entry: String,
    policy_path: PathBuf,
    out: Option<PathBuf>,
    emit_evidence: Option<PathBuf>,
) -> Result<()> {
    let policy = load_policy(policy_path)?;
    let (ir, safeisa) = analyze_binary(&binary, &entry)?;
    let mut capabilities = Vec::new();
    let mut capability_evidence: BTreeMap<String, Vec<EvidenceItem>> = BTreeMap::new();
    let mut external_calls = Vec::new();
    let mut unsupported = Vec::new();
    let mut extra_violations = Vec::new();

    for block in &ir.blocks {
        for op in &block.ops {
            let address = format!("{:#x}", op.source_address.unwrap_or_default());
            match op.op.as_str() {
                "Add" | "Sub" | "Mul" | "And" | "Or" | "Xor" => {
                    capabilities.push("arithmetic".to_string());
                    capability_evidence
                        .entry("arithmetic".to_string())
                        .or_default()
                        .push(EvidenceItem {
                            address,
                            instruction: op.text.clone(),
                            symbol: None,
                        });
                }
                "ExternalCall" => {
                    let symbol = op.symbol.clone().unwrap_or_else(|| "unknown".to_string());
                    let capability = capability_for_symbol(&symbol).map(str::to_string);
                    if let Some(capability_name) = &capability {
                        capabilities.push(capability_name.clone());
                        capability_evidence
                            .entry(capability_name.clone())
                            .or_default()
                            .push(EvidenceItem {
                                address: address.clone(),
                                instruction: op.text.clone(),
                                symbol: Some(symbol.clone()),
                            });
                    }
                    external_calls.push(ExternalCall {
                        symbol,
                        capability,
                        address,
                    });
                }
                "Unsupported" => {
                    capabilities.push("unsupported_instruction".to_string());
                    unsupported.push(UnsupportedInstruction {
                        address: address.clone(),
                        instruction: op.text.clone(),
                    });
                    extra_violations.push(PolicyViolation::with_address(
                        "unsupported_instruction",
                        "unsupported_instruction",
                        address,
                    ));
                }
                _ => {}
            }
        }
    }

    let mut result = evaluate_policy(&policy, capabilities.iter().map(String::as_str));
    result.violations.extend(extra_violations);
    let unique_capabilities: BTreeSet<String> = capabilities.into_iter().collect();
    let evidence = Evidence {
        binary: binary.display().to_string(),
        entry,
        verdict: result.verdict,
        capabilities: unique_capabilities
            .into_iter()
            .map(|name| CapabilityEvidence {
                evidence: capability_evidence.remove(&name).unwrap_or_default(),
                name,
            })
            .collect(),
        external_calls,
        unsupported_instructions: unsupported,
        policy_violations: result.violations,
    };

    if let Some(path) = emit_evidence {
        std::fs::write(path, evidence.to_json()?)?;
    }
    if let Some(path) = out {
        std::fs::write(path, render_report(&evidence, Some(&safeisa)))?;
    }
    println!("SIGIL Verdict: [{}]", verdict_text(evidence.verdict));
    Ok(())
}

fn analyze_binary(binary: &PathBuf, entry: &str) -> Result<(Function, Program)> {
    let loaded = load_function(binary, entry)?;
    let decoded = decode_x86_64(&loaded.code, loaded.address)?;
    let ir = lift_instructions(
        entry,
        &decoded,
        &loaded.call_symbols,
        &loaded.target_symbols,
    );
    let safeisa = emit_safeisa(&ir);
    Ok((ir, safeisa))
}

fn render_ir(ir: &Function) -> String {
    let mut lines = vec![format!("func {}:", ir.name)];
    for block in &ir.blocks {
        lines.push(format!("  block {}:", block.name));
        for op in &block.ops {
            lines.push(format!(
                "    {:#x} {} {}",
                op.source_address.unwrap_or_default(),
                op.op,
                op.text
            ));
        }
    }
    lines.join("\n") + "\n"
}
