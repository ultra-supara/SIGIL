from sigil.assess.evidence import Evidence
from sigil.assess.report import render_report


def test_report_includes_unsupported_instruction_evidence():
    evidence = Evidence(
        binary="fixture.o",
        entry="kernel",
        verdict="WARN",
        unsupported_instructions=[{"address": "0x401000", "instruction": "ud2"}],
    )

    report = render_report(evidence)

    assert "## Unsupported Instructions" in report
    assert "0x401000" in report
    assert "ud2" in report
