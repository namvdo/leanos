#!/usr/bin/env python3
"""Fail-closed compatibility evidence and scheduling regression fixtures."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compatibility", ROOT / "scripts/toolchain-compatibility.py")
assert SPEC is not None and SPEC.loader is not None
compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compat)


class CompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.entries = compat.registry()
        self.revision = "a" * 40
        self.reports = [{
            "schema": compat.SCHEMA, "profile": profile,
            "registry_sha256": compat.profiles.sha256(compat.profiles.DEFAULT_MANIFEST),
            "source_revision": self.revision, "status": "PASS",
            "phases": list(compat.PHASES),
            "semantic": {key: "b" * 64 for key in compat.SEMANTIC_FILES},
            "scenarios": compat.expected_scenarios(),
        } for profile in self.entries.values()]

    def test_complete_matrix_and_different_binary_hashes(self) -> None:
        for index, report in enumerate(self.reports):
            report["binary_sha256"] = str(index) * 64
        compat.compare(self.reports, self.revision)
        self.assertEqual(set(self.entries), {r["profile"] for r in compat.matrix()["include"]})

    def test_reject_incomplete_duplicate_unknown_and_malformed(self) -> None:
        for reports in ([], self.reports[:1], self.reports + self.reports[:1],
                        [None], [{"profile": {"id": []}}]):
            with self.subTest(reports=reports), self.assertRaises(compat.profiles.ProfileError):
                compat.compare(reports, self.revision)
        mutations = {
            "status": "FAIL", "schema": "unknown", "source_revision": "c" * 40,
            "registry_sha256": "d" * 64, "phases": list(compat.PHASES[:-1]),
            "profile": {"id": "unknown"}, "semantic": None, "scenarios": [],
        }
        for key, value in mutations.items():
            reports = copy.deepcopy(self.reports)
            reports[0][key] = value
            with self.subTest(field=key), self.assertRaises(compat.profiles.ProfileError):
                compat.compare(reports, self.revision)

    def test_each_semantic_and_guest_mutation_fails(self) -> None:
        for key in compat.SEMANTIC_FILES:
            reports = copy.deepcopy(self.reports)
            reports[1]["semantic"][key] = "e" * 64
            with self.subTest(contract=key), self.assertRaises(compat.profiles.ProfileError):
                compat.compare(reports, self.revision)
        for key, value in (("id", "invented"), ("status", "FAIL"),
                           ("runner_exit_status", 1), ("result_class", "wrong")):
            reports = copy.deepcopy(self.reports)
            # Even matching bad evidence across *all* compilers must fail.
            for report in reports:
                report["scenarios"][0][key] = value
            with self.subTest(guest=key), self.assertRaises(compat.profiles.ProfileError):
                compat.compare(reports, self.revision)

    def test_retained_contracts_are_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = copy.deepcopy(self.reports[0])
            for name in compat.SEMANTIC_FILES:
                path = directory / f"{name}.txt"
                path.write_text("validated contract\n")
                report["semantic"][name] = compat.profiles.sha256(path)
            path = directory / "report.json"
            compat.write_report(path, report)
            self.assertEqual(compat.read_report(path), report)
            (directory / "oracle.txt").write_text("altered\n")
            with self.assertRaisesRegex(compat.profiles.ProfileError, "altered retained"):
                compat.read_report(path)

    def test_each_phase_fails_fast_and_retains_diagnostics(self) -> None:
        for failed_phase in compat.PHASES:
            with self.subTest(phase=failed_phase), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                output = directory / "report.json"
                commands = iter(compat.PHASES[1:])

                def execute(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
                    phase = next(commands)
                    return subprocess.CompletedProcess(args, 1 if phase == failed_phase else 0)

                with patch.object(compat, "ROOT", directory), \
                     patch.object(compat, "registry", return_value=(self.data, self.entries)), \
                     patch.object(compat, "checked_output", return_value=self.revision), \
                     patch.object(compat, "environment", side_effect=(
                         compat.profiles.ProfileError("environment drift")
                         if failed_phase == "environment" else None)), \
                     patch.object(compat.subprocess, "run", side_effect=execute) as runner:
                    with self.assertRaises(compat.profiles.ProfileError):
                        compat.run(self.data["default_profile"], output)
                report = json.loads(output.read_text())
                index = compat.PHASES.index(failed_phase)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["phases"], list(compat.PHASES[:index]))
                self.assertEqual(runner.call_count, index)
                self.assertIn("completed_at", report)
                self.assertIn("error", report)

    def test_registry_rejects_unknown_tier_borrowed_layout_and_duplicate_keys(self) -> None:
        for key, value in (("evidence_tier", "latest"), ("apt_packages", ["binutils=1"]),
                           ("lean_toolchain", "leanprover/lean4:nightly")):
            data = copy.deepcopy(self.data)
            data["profiles"][1][key] = value
            with self.subTest(field=key), self.assertRaises(compat.profiles.ProfileError):
                compat.profiles.check_manifest(data)
        data = copy.deepcopy(self.data)
        data["profiles"][1]["interfaces"]["direct_port_elf"] = "gcc-reference-v1"
        with self.assertRaisesRegex(compat.profiles.ProfileError, "borrow"):
            compat.profiles.check_manifest(data)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"status":"PASS","status":"FAIL"}')
            with self.assertRaisesRegex(compat.profiles.ProfileError, "duplicate JSON key"):
                compat.profiles.load_json(path)

    def test_candidate_inventory_can_change_without_changing_canonical(self) -> None:
        data = copy.deepcopy(self.data)
        candidate = copy.deepcopy(data["profiles"][1])
        candidate.update(id="clang-candidate", status="candidate")
        candidate["apt_packages"] = list(data["canonical_apt_packages"])
        old = candidate["shared_tools"]["xorriso"]
        new = "xorriso=1:1.5.6-1.1ubuntu4"
        candidate["apt_packages"][candidate["apt_packages"].index(old)] = new
        candidate["shared_tools"]["xorriso"] = new
        candidate["reference_environment"]["ci_image_digest"] = "sha256:" + "e" * 64
        data["profiles"].append(candidate)
        entries = compat.profiles.check_manifest(data)
        self.assertEqual(entries["gcc-reference"], self.entries["gcc-reference"])
        self.assertEqual(entries["clang-candidate"]["shared_tools"]["xorriso"], new)


if __name__ == "__main__":
    unittest.main()
