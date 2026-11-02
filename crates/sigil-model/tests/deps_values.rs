mod common;

use common::*;
use serde_json::{json, Value};
use sigil_model::*;

const REQUESTER: &str = "inst:install/bin/ollama";
const LIBRARY: &str = "inst:install/lib/ollama/libggml-cpu-haswell.so";

fn decode(v: Value) -> Session {
    serde_json::from_value(v).expect("new deps/values JSON must deserialize")
}

fn observed(read: Option<&str>, key: Value) -> Value {
    let s = observed_processes();
    let p = serde_json::to_value(&s.processes[0].process).unwrap();
    let mut origin = json!({"ObservedProcess": {"process": p, "source": "Proc"}});
    if let Some(read) = read {
        origin["ObservedProcess"]["read"] = json!(read);
    }
    json!({
        "id": "value:environment", "process_role": RUNTIME_ROLE,
        "key": key, "value": {"Known": "/usr/local/lib/ollama"},
        "origin": origin, "applies_to": []
    })
}

fn value_session(read: Option<&str>, key: Value) -> Value {
    let mut v = serde_json::to_value(observed_processes()).unwrap();
    v["request"]["observe_env"] = json!(true);
    v["values"] = json!([observed(read, key)]);
    v
}

fn elf_facts(slice: &SliceId, needed: &[&str]) -> Value {
    json!({
        "slice": slice, "container": {"Elf": {
            "abi": {"is_64": true, "little_endian": true, "machine": 62},
            "interp": null, "soname": null, "needed": needed,
            "rpath": [], "runpath": [], "build_id": null, "comment": [],
            "stripped": false, "exports": 0, "imports": [], "data": []
        }}, "go": null, "gaps": []
    })
}

fn candidate_path_proofs(v: &mut Value) {
    for file in v["instances"].as_array_mut().unwrap() {
        if file["root"] != json!(INSTALL_ROOT) {
            continue;
        }
        let parents = match file["path"].as_str().unwrap() {
            "/usr/local/bin/ollama" => json!([{"name": "bin", "dev": 2049, "ino": 52}]),
            "/usr/local/lib/ollama/llama-server"
            | "/usr/local/lib/ollama/libggml-cpu-haswell.so" => {
                json!([{"name": "lib", "dev": 2049, "ino": 50}, {"name": "ollama", "dev": 2049, "ino": 51}])
            }
            path => panic!("add explicit synthetic directory evidence for {path:?}"),
        };
        file["path_proof"] = json!({"root_dev": 2049, "root_ino": 49, "parents": parents});
    }
}

fn candidate_session() -> Value {
    let s = observed_processes();
    let requester = placed(&s, REQUESTER);
    let library = placed(&s, LIBRARY);
    let p = s.processes[0].process.clone();
    let mut v = value_session(
        Some("InitialEnvironment"),
        json!({"Env": "LD_LIBRARY_PATH"}),
    );
    v["binaries"] = json!([
        elf_facts(&requester.slice, &["libggml-cpu-haswell.so"]),
        elf_facts(&library.slice, &[])
    ]);
    v["relations"] = json!([
        {"Declares": {"from": requester.slice, "needed": "libggml-cpu-haswell.so", "kind": "ElfNeeded"}},
        {"Candidate": {
            "from": requester.slice, "needed": "libggml-cpu-haswell.so", "candidate": LIBRARY,
            "via": "LdLibraryPath", "context": {
                "requester": REQUESTER, "search_dir": "/usr/local/lib/ollama",
                "process": p, "values": ["value:environment"], "loader_chain": [REQUESTER],
                "search": {"LdLibraryPath": {"value": "value:environment", "component": 0}}
            }
        }}
    ]);
    candidate_path_proofs(&mut v);
    v["observation"]["mnt_ns"] = json!(1234);
    for process in v["processes"].as_array_mut().unwrap() {
        process["mnt_ns"] = json!({"Inode": 1234});
    }
    v
}

fn reject(v: Value, needle: &str) {
    let s = decode(v);
    let errors = errors(&s);
    assert!(
        errors.iter().any(|e| e.to_string().contains(needle)),
        "expected {needle:?}, got {}",
        render(&errors)
    );
}

#[test]
fn legacy_observations_and_candidates_keep_their_json() {
    let v = value_session(None, json!({"Env": "LD_LIBRARY_PATH"}));
    let s = decode(v.clone());
    assert_valid(&s);
    assert_eq!(serde_json::to_value(s).unwrap(), v);
    let s = observed_processes();
    let from = placed(&s, REQUESTER).slice;
    let old = json!({"Candidate": {
        "from": from, "needed": "old-declared-name", "candidate": LIBRARY, "via": "Runpath"
    }});
    let r: Relation = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(&r).unwrap(), old);
    let mut s = s;
    s.relations.push(r);
    assert_valid(&s); // no new producer constraints on a context-free legacy edge
    let mut legacy_count = 0;
    for (name, s) in examples() {
        let legacy = name
            .split_once('-')
            .and_then(|(number, _)| number.parse::<u8>().ok())
            .is_some_and(|number| (1..=20).contains(&number));
        if !legacy {
            continue;
        }
        legacy_count += 1;
        for file in &s.instances {
            assert_eq!(file.path_proof, None, "{name}: {}", file.id);
        }
        let v = serde_json::to_value(&s).unwrap();
        for file in v["instances"].as_array().unwrap() {
            assert!(file.get("path_proof").is_none(), "{name}: {file}");
        }
        for p in v["processes"].as_array().unwrap() {
            assert!(p.get("mnt_ns").is_none());
        }
        if let Some(binaries) = v["binaries"].as_array() {
            for b in binaries {
                if let Some(elf) = b["container"].get("Elf") {
                    assert!(elf.get("abi").is_none());
                }
            }
        }
    }
    assert_eq!(legacy_count, 20);
}

#[test]
fn initial_environment_cannot_settle_a_current_value_condition() {
    for actual in [json!({"Known": ""}), json!("Absent")] {
        let mut v = value_session(
            Some("InitialEnvironment"),
            json!({"Env": "LD_LIBRARY_PATH"}),
        );
        v["values"][0]["value"] = actual;
        let s = decode(v);
        assert_valid(&s);
        for needs in [ValueNeed::Known, ValueNeed::Absent] {
            assert_eq!(
                s.settles(&CondEvidence::Value {
                    value: id("value:environment"),
                    needs
                })
                .unwrap(),
                Settles::Neither
            );
        }
    }
    let s = decode(value_session(None, json!({"Env": "LD_LIBRARY_PATH"})));
    assert_eq!(
        s.settles(&CondEvidence::Value {
            value: id("value:environment"),
            needs: ValueNeed::Known
        })
        .unwrap(),
        Settles::Met
    );
}

#[test]
fn read_details_must_agree_with_key_mode_source_opt_in_and_process() {
    for (read, key) in [
        ("InitialEnvironment", json!("Cwd")),
        ("Cwd", json!("User")),
        ("EffectiveUid", json!("Group")),
        ("EffectiveGid", json!({"Env": "GGML_BACKEND_PATH"})),
    ] {
        reject(
            value_session(Some(read), key),
            "read does not match value key",
        );
    }
    let mut v = value_session(
        Some("InitialEnvironment"),
        json!({"Env": "LD_LIBRARY_PATH"}),
    );
    v["request"]["mode"] = json!("Static");
    reject(v, "requires observe mode");
    let mut v = value_session(
        Some("InitialEnvironment"),
        json!({"Env": "LD_LIBRARY_PATH"}),
    );
    v["request"]["observe_env"] = json!(false);
    reject(v, "requires observe_env");
    let mut v = value_session(
        Some("InitialEnvironment"),
        json!({"Env": "LD_LIBRARY_PATH"}),
    );
    v["values"][0]["origin"]["ObservedProcess"]["source"] = json!("File");
    reject(v, "requires Proc source");
    let mut v = value_session(
        Some("InitialEnvironment"),
        json!({"Env": "LD_LIBRARY_PATH"}),
    );
    v["values"][0]["origin"]["ObservedProcess"]["process"]["start_ticks"] = json!(999);
    reject(v, "process");
    for (read, key) in [
        ("Cwd", json!("Cwd")),
        ("EffectiveUid", json!("User")),
        ("EffectiveGid", json!("Group")),
    ] {
        let mut v = value_session(Some(read), key);
        v["request"]["observe_env"] = json!(false);
        assert_valid(&decode(v));
    }
}

#[test]
fn contextual_candidates_validate_and_reject_forged_references() {
    assert_valid(&decode(candidate_session()));
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["requester"] = json!(LIBRARY);
    reject(v, "requester does not own from slice");
    for (field, replacement, expected) in [
        ("requester", json!("inst:absent"), "instance"),
        ("values", json!(["value:absent"]), "value"),
        (
            "loader_chain",
            json!(["inst:absent", REQUESTER]),
            "instance",
        ),
        (
            "loader_chain",
            json!([]),
            "loader_chain must end at requester",
        ),
        (
            "loader_chain",
            json!([REQUESTER, REQUESTER]),
            "loader_chain repeats",
        ),
        ("process", Value::Null, "values require a process"),
    ] {
        let mut v = candidate_session();
        v["relations"][1]["Candidate"]["context"][field] = replacement;
        reject(v, expected);
    }
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["process"]["boot_id"] = json!("another-boot");
    reject(v, "process");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["needed"] = json!("not-declared.so");
    reject(v, "matching ELF declaration");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["via"] = json!("DirectPath");
    reject(v, "DirectPath must match a dependency containing a slash");
}

#[test]
fn contextual_inputs_cannot_borrow_another_process_or_configuration() {
    let mut v = candidate_session();
    v["values"][0]["origin"]["ObservedProcess"]["process"] = v["processes"][1]["process"].clone();
    reject(v, "input is not an observed value of this process");
    let mut v = candidate_session();
    v["values"][0]["value"] = json!({"Unknown": {"reason": "InsufficientEvidence"}});
    reject(v, "input is unknown");
    let mut v = candidate_session();
    v["values"][0]["origin"]["ObservedProcess"]
        .as_object_mut()
        .unwrap()
        .remove("read");
    reject(v, "input read is not a dependency input");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["process"] = v["processes"][1]["process"].clone();
    reject(v, "input is not an observed value of this process");
}

#[test]
fn contextual_candidates_need_stable_read_elf_and_compatible_supported_abi() {
    let s = observed_processes();
    let library = s
        .instances
        .iter()
        .position(|i| i.id.as_str() == LIBRARY)
        .unwrap();
    let mut v = candidate_session();
    v["instances"][library]["stability"] = json!("ChangedDuringRead");
    reject(v, "stable read ELF placement");
    let mut v = candidate_session();
    v["instances"][library]["content"] = json!({"NotRead": {"why": "BudgetExceeded"}});
    reject(v, "stable read ELF placement");
    for abi in [
        Value::Null,
        json!({"is_64": false, "little_endian": true, "machine": 62}),
        json!({"is_64": true, "little_endian": false, "machine": 62}),
        json!({"is_64": true, "little_endian": true, "machine": 183}),
        json!({"is_64": true, "little_endian": true, "machine": 999}),
    ] {
        let mut v = candidate_session();
        v["binaries"][1]["container"]["Elf"]["abi"] = abi;
        reject(v, "supported matching ELF ABI");
    }
    let mut v = candidate_session();
    let artifact = s
        .artifacts
        .iter()
        .position(|a| a.id == placed(&s, LIBRARY).artifact)
        .unwrap();
    v["artifacts"][artifact]["format"]["Elf"]["kind"] = json!("Exec");
    reject(v, "candidate must be ET_DYN");
}

#[test]
fn namespace_is_independent_of_mapping_count_and_cwd_needs_same_mount_ns() {
    let mut v = candidate_session();
    v["values"][0]["value"] = json!({"Known": "lib/ollama"});
    add_cwd_input(&mut v, "/usr/local");
    v["relations"][1]["Candidate"]["context"]["values"] =
        json!(["value:environment", "value:another"]);
    assert_valid(&decode(v.clone()));
    v["processes"][0]["mnt_ns"] = json!({"Inode": 5678});
    reject(v, "cwd requires the collector mount namespace");
    let mut v = serde_json::to_value(observed_processes()).unwrap();
    v["processes"][0]["mappings"] = json!([]);
    v["processes"][0]["maps_read"] = json!("NotRead");
    v["processes"][0]["mnt_ns"] = json!({"Inode": 1234});
    let process = v["processes"][0]["process"].clone();
    for coverage in v["coverage"].as_array_mut().unwrap() {
        if coverage["check"] == "processes.observed"
            && coverage["scope"] == json!({"Process": process})
        {
            coverage["state"] = json!({"Partial": {"missing": ["fixture maps not read"]}});
        }
    }
    v["outcome"]["completeness"] =
        json!({"Incomplete": {"missing_required": ["processes.observed"], "gaps": []}});
    assert_valid(&decode(v));
}

#[test]
fn recorded_parent_proof_json_is_a_supported_instance_field() {
    let s = observed_processes();
    let file = s
        .instances
        .iter()
        .find(|i| i.id.as_str() == REQUESTER)
        .unwrap();
    let mut v = serde_json::to_value(file).unwrap();
    v["path_proof"] = json!({
        "root_dev": 2049, "root_ino": 49,
        "parents": [{"name": "bin", "dev": 2049, "ino": 52}]
    });
    let decoded: FileInstance = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), v);
}

fn candidate_needed(v: &mut Value, needed: &str) {
    v["relations"][0]["Declares"]["needed"] = json!(needed);
    v["relations"][1]["Candidate"]["needed"] = json!(needed);
    // Keep this helper's declared container facts internally consistent too.
    v["binaries"][0]["container"]["Elf"]["needed"] = json!([needed]);
}

#[test]
fn contextual_search_directory_must_reach_the_exact_candidate() {
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["search_dir"] = json!("/usr/local/bin");
    reject(v, "dependency lookup does not reach the recorded candidate");
}

#[test]
fn contextual_search_uses_recorded_link_evidence_and_physical_target() {
    let mut v = candidate_session();
    let mut alias = v["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(LIBRARY))
        .unwrap()
        .clone();
    alias["id"] = json!("inst:install/alias");
    alias["path"] = json!("/usr/local/alias");
    alias["stat"]["mode"] = json!(0o120777);
    alias["stat"]["ino"] = json!(1100);
    alias["stat"]["size"] = json!(10);
    alias["link_chain"] =
        json!([{"path": "/usr/local/alias", "target": "lib/ollama", "uid": 0, "mode": 0o120777}]);
    alias["resolved"] = json!("lib/ollama");
    alias["content"] = json!({"NotRead": {"why": "NotFollowed"}});
    alias["discovered_by"] = json!(["Walk"]);
    alias["path_proof"] = json!({"root_dev": 2049, "root_ino": 49, "parents": []});
    v["instances"].as_array_mut().unwrap().push(alias);
    v["relations"][1]["Candidate"]["context"]["search_dir"] = json!("/usr/local/alias");
    v["values"][0]["value"] = json!({"Known": "/usr/local/alias"});
    assert_valid(&decode(v.clone()));
    // No host filesystem is consulted: removing this recorded link removes its authority.
    v["instances"]
        .as_array_mut()
        .unwrap()
        .retain(|i| i["id"] != json!("inst:install/alias"));
    reject(v, "dependency path: unknown ancestor");
}

#[test]
fn direct_path_reconstructs_original_name_and_checks_its_recorded_parent() {
    let mut v = candidate_session();
    candidate_needed(&mut v, "/usr/local/lib/ollama/libggml-cpu-haswell.so");
    v["relations"][1]["Candidate"]["via"] = json!("DirectPath");
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    v["relations"][1]["Candidate"]["context"]["process"] = Value::Null;
    v["relations"][1]["Candidate"]["context"]["search"] = json!("DirectPath");
    assert_valid(&decode(v.clone()));
    v["relations"][1]["Candidate"]["context"]["search_dir"] = json!("/usr/local/bin");
    reject(
        v,
        "DirectPath search_dir does not match the expanded dependency parent",
    );
    let mut v = candidate_session();
    candidate_needed(&mut v, "$ORIGIN/../lib/ollama/libggml-cpu-haswell.so");
    v["relations"][1]["Candidate"]["via"] = json!("DirectPath");
    v["relations"][1]["Candidate"]["context"]["search_dir"] = json!("/usr/local/bin/../lib/ollama");
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    v["relations"][1]["Candidate"]["context"]["process"] = Value::Null;
    v["relations"][1]["Candidate"]["context"]["search"] = json!("DirectPath");
    assert_valid(&decode(v));
}

#[test]
fn relative_direct_path_requires_qualified_same_process_cwd() {
    let mut v = candidate_session();
    candidate_needed(&mut v, "lib/ollama/libggml-cpu-haswell.so");
    v["relations"][1]["Candidate"]["via"] = json!("DirectPath");
    v["relations"][1]["Candidate"]["context"]["search"] = json!("DirectPath");
    v["values"][0]["key"] = json!("Cwd");
    v["values"][0]["value"] = json!({"Known": "/usr/local"});
    v["values"][0]["origin"]["ObservedProcess"]["read"] = json!("Cwd");
    v["observation"]["mnt_ns"] = json!(1234);
    v["processes"][0]["mnt_ns"] = json!({"Inode": 1234});
    assert_valid(&decode(v.clone()));
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    reject(v, "qualified same-process cwd required");
}

#[test]
fn slash_free_tokens_never_gain_direct_path_authority_from_expansion() {
    for needed in ["$ORIGIN", "${ORIGIN}", "$LIB"] {
        let mut v = candidate_session();
        candidate_needed(&mut v, needed);
        v["relations"][1]["Candidate"]["via"] = json!("DefaultDir");
        reject(v.clone(), "slash-free dependency token is not modeled");
        v["relations"][1]["Candidate"]["via"] = json!("DirectPath");
        reject(v, "DirectPath must match a dependency containing a slash");
    }
}

const CHAIN_ROOT: &str = "inst:install/lib/ollama/llama-server";
const TAIL: &str = "inst:install/lib/ollama/libtail.so";

fn add_cwd_input(v: &mut Value, text: &str) {
    let mut cwd = v["values"][0].clone();
    cwd["id"] = json!("value:another");
    cwd["key"] = json!("Cwd");
    cwd["value"] = json!({"Known": text});
    cwd["origin"]["ObservedProcess"]["read"] = json!("Cwd");
    v["values"].as_array_mut().unwrap().push(cwd);
}

// Root llama-server -> compatible library -> another placement of that library's ELF.
// Both edges have real DT_NEEDED rows and separately recorded qualified search inputs.
fn two_hop_session() -> Value {
    let s = observed_processes();
    let root = placed(&s, CHAIN_ROOT);
    let library = placed(&s, LIBRARY);
    let mut v = candidate_session();
    let process = v["processes"][1]["process"].clone();
    v["processes"][1]["mnt_ns"] = json!({"Inode": 1234});
    v["values"][0]["origin"]["ObservedProcess"]["process"] = process.clone();
    v["values"][0]["process_role"] = json!(format!("observed:{}", "a".repeat(64)));
    v["values"][0]["value"] = json!({"Known": "lib/ollama"});
    add_cwd_input(&mut v, "/usr/local");
    v["binaries"] = json!([
        elf_facts(&root.slice, &["libggml-cpu-haswell.so"]),
        elf_facts(&library.slice, &["libtail.so"]),
    ]);
    v["relations"][0]["Declares"]["from"] = json!(root.slice);
    let edge = &mut v["relations"][1]["Candidate"];
    edge["from"] = json!(root.slice);
    edge["context"]["requester"] = json!(CHAIN_ROOT);
    edge["context"]["process"] = process;
    edge["context"]["loader_chain"] = json!([CHAIN_ROOT]);
    edge["context"]["values"] = json!(["value:environment", "value:another"]);
    let mut tail = v["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(LIBRARY))
        .unwrap()
        .clone();
    tail["id"] = json!(TAIL);
    tail["path"] = json!("/usr/local/lib/ollama/libtail.so");
    tail["stat"]["ino"] = json!(1201);
    v["instances"].as_array_mut().unwrap().push(tail);
    let mut edge = v["relations"][1].clone();
    edge["Candidate"]["from"] = json!(library.slice);
    edge["Candidate"]["needed"] = json!("libtail.so");
    edge["Candidate"]["candidate"] = json!(TAIL);
    edge["Candidate"]["context"]["requester"] = json!(LIBRARY);
    edge["Candidate"]["context"]["loader_chain"] = json!([CHAIN_ROOT, LIBRARY]);
    v["relations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"Declares": {
            "from": library.slice, "needed": "libtail.so", "kind": "ElfNeeded",
        }}));
    v["relations"].as_array_mut().unwrap().push(edge);
    v
}

fn inherited_rpath_session() -> Value {
    let mut v = two_hop_session();
    v["binaries"][0]["container"]["Elf"]["rpath"] = json!(["$ORIGIN"]);
    for row in v["relations"].as_array_mut().unwrap() {
        if let Some(edge) = row.get_mut("Candidate") {
            edge["via"] = json!("Rpath");
            edge["context"]["process"] = Value::Null;
            edge["context"]["values"] = json!([]);
            edge["context"]["search"] =
                json!({"Rpath": {"owner": CHAIN_ROOT, "entry": 0, "component": 0}});
        }
    }
    v
}

#[test]
fn runpath_and_rpath_witnesses_must_name_actual_unsuppressed_settings() {
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["via"] = json!("Runpath");
    v["relations"][1]["Candidate"]["context"]["search"] =
        json!({"Runpath": {"entry": 0, "component": 0}});
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    reject(v.clone(), "search witness entry/component is out of range");
    v["binaries"][0]["container"]["Elf"]["runpath"] = json!(["/usr/local/lib/ollama"]);
    assert_valid(&decode(v.clone()));
    v["binaries"][0]["container"]["Elf"]["runpath"] = json!(["/unrelated"]);
    reject(v, "search rule does not derive the recorded directory");

    let v = inherited_rpath_session();
    assert_valid(&decode(v.clone()));
    let mut changed = v.clone();
    changed["binaries"][1]["container"]["Elf"]["runpath"] = json!(["/usr/local/lib/ollama"]);
    reject(changed, "requester RUNPATH suppresses RPATH search");
    let mut changed = v.clone();
    changed["binaries"][0]["container"]["Elf"]["runpath"] = json!(["/usr/local/lib/ollama"]);
    reject(changed, "owner RUNPATH suppresses its RPATH");
    let mut changed = v;
    changed["relations"][3]["Candidate"]["context"]["search"]["Rpath"]["owner"] = json!(REQUESTER);
    reject(changed, "RPATH owner is outside loader_chain");
}

#[test]
fn default_directory_and_environment_witnesses_cannot_invent_search_stages() {
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["via"] = json!("DefaultDir");
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    v["relations"][1]["Candidate"]["context"]["search"] = json!({"DefaultDir": {"index": 0}});
    reject(
        v.clone(),
        "search rule does not derive the recorded directory",
    );
    v["relations"][1]["Candidate"]["context"]["search"] = json!({"DefaultDir": {"index": 255}});
    reject(v, "default-directory witness is out of range");
    let mut v = candidate_session();
    v["values"][0]["value"] = json!({"Known": "/unrelated"});
    reject(v, "search rule does not derive the recorded directory");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["search"]["LdLibraryPath"]["value"] =
        json!("value:missing");
    reject(v, "LD_LIBRARY_PATH witness is not a contextual input");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]["search"]["LdLibraryPath"]["component"] =
        json!(u64::MAX);
    reject(v, "search witness environment component is out of range");
}

#[test]
fn detailed_candidates_require_a_search_witness_while_legacy_edges_keep_their_boundary() {
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]["context"]
        .as_object_mut()
        .unwrap()
        .remove("search");
    let error = serde_json::from_value::<Session>(v)
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing field `search`"), "{error}");
    let mut v = candidate_session();
    v["relations"][1]["Candidate"]
        .as_object_mut()
        .unwrap()
        .remove("context");
    assert_valid(&decode(v)); // no new producer check: preserved legacy context=None contract
}

#[test]
fn source_components_expand_their_owners_origin_and_only_the_needed_cwd() {
    let mut v = inherited_rpath_session();
    // A genuinely inherited owner ORIGIN remains the root's placement, not a child ID.
    assert_valid(&decode(v.clone()));
    v["binaries"][0]["container"]["Elf"]["rpath"] = json!(["$LIB"]);
    reject(v, "only ORIGIN is modeled");
    let mut v = candidate_session();
    v["values"][0]["value"] = json!({"Known": "unrelated;/usr/local/lib/ollama"});
    v["relations"][1]["Candidate"]["context"]["search"]["LdLibraryPath"]["component"] = json!(1);
    assert_valid(&decode(v.clone()));
    v["relations"][1]["Candidate"]["context"]["search"]["LdLibraryPath"]["component"] = json!(0);
    reject(v, "qualified same-process cwd required");
    let mut v = candidate_session();
    add_cwd_input(&mut v, "/usr/local");
    v["relations"][1]["Candidate"]["context"]["values"] =
        json!(["value:environment", "value:another"]);
    reject(
        v.clone(),
        "context values do not exactly match search witness inputs",
    );
    v["values"][0]["value"] = json!({"Known": "lib/ollama"});
    assert_valid(&decode(v));
}

#[test]
fn loader_chain_requires_a_grounded_exact_prefix_and_ignores_relation_order() {
    let mut v = two_hop_session();
    assert_valid(&decode(v.clone()));
    v["relations"].as_array_mut().unwrap().reverse();
    assert_valid(&decode(v));
    let mut v = two_hop_session();
    v["relations"].as_array_mut().unwrap().remove(1); // declaration alone is insufficient
    reject(v, "loader_chain has no locally valid Candidate");
    let mut v = two_hop_session();
    v["relations"][1]["Candidate"]
        .as_object_mut()
        .unwrap()
        .remove("context");
    reject(v, "loader_chain has no locally valid Candidate");
}

#[test]
fn invalid_rule_or_declaration_cannot_ground_a_childs_loader_chain() {
    let mut v = two_hop_session();
    v["relations"][1]["Candidate"]["via"] = json!("Runpath");
    v["relations"][1]["Candidate"]["context"]["search"] =
        json!({"Runpath": {"entry": 0, "component": 0}});
    reject(v, "loader_chain has no locally valid Candidate");
    let mut v = two_hop_session();
    v["binaries"][0]["container"]["Elf"]["needed"] = json!([]);
    reject(v, "loader_chain has no locally valid Candidate");
    let mut v = two_hop_session();
    v["relations"][1]["Candidate"]["context"]["process"] = Value::Null;
    reject(v, "loader_chain has no locally valid Candidate");
}

#[test]
fn cyclic_or_cross_process_chain_claims_do_not_bootstrap_provenance() {
    let mut v = inherited_rpath_session();
    v["relations"][1]["Candidate"]["context"]["loader_chain"] = json!([LIBRARY, CHAIN_ROOT]);
    // Both rows now demand an absent shorter prefix; neither can ground the other.
    reject(v, "loader_chain has no locally valid Candidate");
    let mut v = two_hop_session();
    let other = v["processes"][0]["process"].clone();
    v["relations"][3]["Candidate"]["context"]["process"] = other;
    reject(v, "process seed is not the recorded executable");
}

#[test]
fn canonicalization_sorts_actual_inputs_and_preserves_a_grounded_loader_chain() {
    let mut s = decode(two_hop_session());
    assert_valid(&s);
    s.canonicalize();
    let written = serde_json::to_value(s).unwrap();
    let edge = written["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|r| {
            let edge = r.get("Candidate")?;
            (edge["candidate"] == json!(TAIL)).then_some(edge)
        })
        .unwrap();
    assert_eq!(
        edge["context"]["values"],
        json!(["value:another", "value:environment"])
    );
    assert_eq!(
        edge["context"]["loader_chain"],
        json!([CHAIN_ROOT, LIBRARY])
    );
}

#[test]
fn default_directory_witness_accepts_only_a_matching_collected_default_path() {
    let mut v = candidate_session();
    let mut target = v["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(LIBRARY))
        .unwrap()
        .clone();
    target["id"] = json!("inst:default-lib/libggml-cpu-haswell.so");
    target["root"] = json!("default-lib");
    target["path"] = json!("/lib/libggml-cpu-haswell.so");
    target["stat"]["ino"] = json!(1300);
    target["path_proof"] = json!({"root_dev": 2049, "root_ino": 70, "parents": []});
    v["request"]["roots"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "default-lib", "path": "/lib"}));
    v["instances"].as_array_mut().unwrap().push(target);
    let edge = &mut v["relations"][1]["Candidate"];
    edge["candidate"] = json!("inst:default-lib/libggml-cpu-haswell.so");
    edge["via"] = json!("DefaultDir");
    edge["context"]["values"] = json!([]);
    edge["context"]["process"] = Value::Null;
    edge["context"]["search_dir"] = json!("/lib");
    edge["context"]["search"] = json!({"DefaultDir": {"index": 0}});
    assert_valid(&decode(v.clone()));
    v["relations"][1]["Candidate"]["context"]["search"]["DefaultDir"]["index"] = json!(1);
    reject(v, "search rule does not derive the recorded directory");
}

fn replace_text(v: &mut Value, from: &str, to: &str) {
    match v {
        Value::String(text) if text == from => *text = to.into(),
        Value::Array(rows) => {
            for row in rows {
                replace_text(row, from, to);
            }
        }
        Value::Object(fields) => {
            for row in fields.values_mut() {
                replace_text(row, from, to);
            }
        }
        _ => (),
    }
}

#[test]
fn inherited_rpath_expands_the_recorded_owners_origin_in_a_different_directory() {
    let mut v = inherited_rpath_session();
    let relocated = "inst:install/lib/alt/libggml-cpu-haswell.so";
    replace_text(&mut v, LIBRARY, relocated);
    let file = v["instances"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|i| i["id"] == json!(relocated))
        .unwrap();
    file["path"] = json!("/usr/local/lib/alt/libggml-cpu-haswell.so");
    file["path_proof"]["parents"] = json!([
        {"name": "lib", "dev": 2049, "ino": 50},
        {"name": "alt", "dev": 2049, "ino": 53},
    ]);
    v["binaries"][0]["container"]["Elf"]["rpath"] = json!(["$ORIGIN/../alt", "$ORIGIN"]);
    v["relations"][1]["Candidate"]["context"]["search_dir"] = json!("/usr/local/lib/ollama/../alt");
    v["relations"][3]["Candidate"]["context"]["search"]["Rpath"]["entry"] = json!(1);
    assert_valid(&decode(v.clone()));
    // Choosing the child as owner would expand /usr/local/lib/alt, not the recorded directory.
    v["binaries"][1]["container"]["Elf"]["rpath"] = json!(["/unused", "$ORIGIN"]);
    v["relations"][3]["Candidate"]["context"]["search"]["Rpath"]["owner"] = json!(relocated);
    reject(v, "search rule does not derive the recorded directory");
}

#[test]
fn empty_runpath_component_requires_and_records_exactly_its_cwd_input() {
    let mut v = candidate_session();
    add_cwd_input(&mut v, "/usr/local/lib/ollama");
    v["binaries"][0]["container"]["Elf"]["runpath"] = json!([":"]);
    v["relations"][1]["Candidate"]["via"] = json!("Runpath");
    v["relations"][1]["Candidate"]["context"]["search"] =
        json!({"Runpath": {"entry": 0, "component": 1}});
    v["relations"][1]["Candidate"]["context"]["values"] = json!(["value:another"]);
    assert_valid(&decode(v.clone()));
    v["relations"][1]["Candidate"]["context"]["values"] = json!([]);
    reject(v, "qualified same-process cwd required");
}

#[test]
fn new_environment_sources_and_observation_roles_obey_the_structural_boundary() {
    reject(
        value_session(Some("InitialEnvironment"), json!({"Env": "PATH"})),
        "key is not allowlisted",
    );
    let mut v = value_session(Some("Cwd"), json!("Cwd"));
    v["values"][0]["process_role"] = json!("unrelated parent role");
    reject(v, "neither this process's role nor an observation label");
    let mut v = value_session(Some("Cwd"), json!("Cwd"));
    v["values"][0]["origin"]["ObservedProcess"]["process"] = v["processes"][1]["process"].clone();
    v["values"][0]["process_role"] = json!(format!("observed:{}", "a".repeat(64)));
    assert_valid(&decode(v.clone()));
    v["values"][0]["process_role"] = json!(format!("observed:{}", "A".repeat(64)));
    reject(v, "neither this process's role nor an observation label");
}

#[test]
fn recorded_path_proof_is_optional_on_read_and_omitted_when_none() {
    let s = observed_processes();
    let file = s
        .instances
        .iter()
        .find(|i| i.id.as_str() == REQUESTER)
        .unwrap();
    assert_eq!(file.path_proof, None);
    let old = serde_json::to_value(file).unwrap();
    assert!(old.get("path_proof").is_none());
    let decoded: FileInstance = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(decoded.path_proof, None);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), old);

    let proof = RecordedPathProof {
        root_dev: 2049,
        root_ino: 49,
        parents: vec![RecordedDirectory {
            name: t("bin"),
            dev: 2049,
            ino: 52,
        }],
    };
    let mut with_proof = old.clone();
    with_proof["path_proof"] = json!({
        "root_dev": 2049, "root_ino": 49,
        "parents": [{"name": "bin", "dev": 2049, "ino": 52}]
    });
    let decoded: FileInstance = serde_json::from_value(with_proof.clone()).unwrap();
    assert_eq!(decoded.path_proof, Some(proof));
    assert_eq!(serde_json::to_value(&decoded).unwrap(), with_proof);

    let mut explicit_null = old.clone();
    explicit_null["path_proof"] = Value::Null;
    let decoded: FileInstance = serde_json::from_value(explicit_null).unwrap();
    assert_eq!(decoded.path_proof, None);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), old);
}

#[test]
fn the_new_observation_check_cannot_be_downgraded_by_removing_read() {
    let mut v = value_session(None, json!({"Env": "LD_LIBRARY_PATH"}));
    v["coverage"].as_array_mut().unwrap().push(json!({
        "check": "values.observed", "scope": "Audit", "state": "Complete", "budget": null
    }));
    reject(v, "values.observed requires explicit read provenance");
    let mut v = value_session(None, json!({"Env": "LD_LIBRARY_PATH"}));
    v["request"]["required_checks"]
        .as_array_mut()
        .unwrap()
        .push(json!("values.observed"));
    reject(v, "values.observed requires explicit read provenance");
}

#[test]
fn new_namespace_evidence_cannot_contradict_a_decided_mapping_claim() {
    let mut v = serde_json::to_value(observed_processes()).unwrap();
    v["observation"]["mnt_ns"] = json!(1234);
    v["processes"][0]["mnt_ns"] = json!({"Inode": 5678});
    reject(
        v.clone(),
        "mapping namespace claim contradicts process.mnt_ns",
    );
    for mapping in v["processes"][0]["mappings"].as_array_mut().unwrap() {
        mapping["same_mount_ns"] =
            json!({"No": {"basis": {"Observed": {"source": "Proc"}}, "unresolved": []}});
    }
    assert_valid(&decode(v));
}
