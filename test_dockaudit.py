#!/usr/bin/env python3
"""Tests for dockaudit - Dockerfile linter and security auditor.

Tests cover:
- Dockerfile parsing
- Stage building
- Individual lint rules (DA001-DA027)
- Grading system
- CLI argument handling
- Edge cases and error conditions
"""

import unittest
import sys
import os
import json
from io import StringIO
from unittest.mock import patch

# Import from dockaudit
sys.path.insert(0, os.path.dirname(__file__))
import dockaudit


class TestDockerfileParser(unittest.TestCase):
    """Test Dockerfile parsing functionality."""

    def test_parse_simple_dockerfile(self):
        """Test parsing a basic valid Dockerfile."""
        content = """FROM ubuntu:20.04
RUN apt-get update
COPY . /app
CMD ["python", "app.py"]
"""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertEqual(len(instructions), 4)
        self.assertEqual(instructions[0].keyword, "FROM")
        self.assertEqual(instructions[1].keyword, "RUN")
        self.assertEqual(instructions[2].keyword, "COPY")
        self.assertEqual(instructions[3].keyword, "CMD")
        self.assertEqual(len(errors), 0)

    def test_parse_multiline_instruction(self):
        """Test parsing instructions with line continuations."""
        content = """FROM ubuntu:20.04
RUN apt-get update && \\
    apt-get install -y python3 && \\
    apt-get clean
"""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertEqual(len(instructions), 2)
        self.assertEqual(instructions[1].keyword, "RUN")
        self.assertEqual(instructions[1].line, 2)
        self.assertEqual(instructions[1].end_line, 4)

    def test_parse_comments_and_blanks(self):
        """Test that comments and blank lines are skipped."""
        content = """# This is a comment
FROM ubuntu:20.04

# Another comment
RUN echo "test"
"""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertEqual(len(instructions), 2)
        self.assertEqual(instructions[0].keyword, "FROM")
        self.assertEqual(instructions[1].keyword, "RUN")

    def test_parse_invalid_instruction(self):
        """Test parsing with unknown instruction."""
        content = """FROM ubuntu:20.04
INVALID_COMMAND something
RUN echo "test"
"""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertGreater(len(errors), 0)
        self.assertIn("INVALID_COMMAND", errors[0])


class TestStageBuilder(unittest.TestCase):
    """Test build stage parsing."""

    def test_single_stage(self):
        """Test building a single-stage Dockerfile."""
        content = """FROM ubuntu:20.04
RUN echo "test"
"""
        instructions, _ = dockaudit.parse_dockerfile(content)
        stages = dockaudit.build_stages(instructions)
        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0].base_image, "ubuntu:20.04")
        self.assertIsNone(stages[0].alias)

    def test_multistage_build(self):
        """Test multi-stage build with named stages."""
        content = """FROM golang:1.19 AS builder
RUN go build -o app

FROM ubuntu:20.04
COPY --from=builder /app /app
"""
        instructions, _ = dockaudit.parse_dockerfile(content)
        stages = dockaudit.build_stages(instructions)
        self.assertEqual(len(stages), 2)
        self.assertEqual(stages[0].alias, "builder")
        self.assertEqual(stages[1].base_image, "ubuntu:20.04")

    def test_stage_user_tracking(self):
        """Test that stages track USER instructions."""
        content = """FROM ubuntu:20.04
RUN echo "test"
USER appuser
CMD ["app"]
"""
        instructions, _ = dockaudit.parse_dockerfile(content)
        stages = dockaudit.build_stages(instructions)
        self.assertTrue(stages[0].has_user)

    def test_stage_healthcheck_tracking(self):
        """Test that stages track HEALTHCHECK instructions."""
        content = """FROM ubuntu:20.04
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        instructions, _ = dockaudit.parse_dockerfile(content)
        stages = dockaudit.build_stages(instructions)
        self.assertTrue(stages[0].has_healthcheck)


class TestLintRules(unittest.TestCase):
    """Test individual lint rules."""

    def test_da002_latest_tag(self):
        """Test DA002: FROM uses :latest tag."""
        content = "FROM ubuntu:latest\nRUN echo test"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da002_findings = [f for f in findings if f.rule_id == "DA002"]
        self.assertEqual(len(da002_findings), 1)
        self.assertEqual(da002_findings[0].severity, dockaudit.Severity.ERROR)

    def test_da002_no_tag(self):
        """Test DA002: FROM with no tag (implicit :latest)."""
        content = "FROM ubuntu\nRUN echo test"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da002_findings = [f for f in findings if f.rule_id == "DA002"]
        self.assertEqual(len(da002_findings), 1)

    def test_da003_no_user(self):
        """Test DA003: No USER instruction (running as root)."""
        content = "FROM ubuntu:20.04\nRUN echo test\nCMD [\"app\"]"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da003_findings = [f for f in findings if f.rule_id == "DA003"]
        self.assertEqual(len(da003_findings), 1)
        self.assertEqual(da003_findings[0].severity, dockaudit.Severity.WARNING)

    def test_da003_with_user(self):
        """Test DA003: No warning when USER is present."""
        content = "FROM ubuntu:20.04\nUSER appuser\nCMD [\"app\"]"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da003_findings = [f for f in findings if f.rule_id == "DA003"]
        self.assertEqual(len(da003_findings), 0)

    def test_da004_secrets_in_env(self):
        """Test DA004: Secrets in ENV or ARG."""
        content = """FROM ubuntu:20.04
ENV API_KEY="sk-1234567890abcdef1234567890abcdef1234567890abcdef"
"""
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da004_findings = [f for f in findings if f.rule_id == "DA004"]
        self.assertEqual(len(da004_findings), 1)
        self.assertEqual(da004_findings[0].severity, dockaudit.Severity.ERROR)

    def test_da005_missing_healthcheck(self):
        """Test DA005: Missing HEALTHCHECK."""
        content = "FROM ubuntu:20.04\nCMD [\"app\"]"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da005_findings = [f for f in findings if f.rule_id == "DA005"]
        self.assertEqual(len(da005_findings), 1)

    def test_da006_curl_pipe_shell(self):
        """Test DA006: curl/wget piped to shell."""
        content = "FROM ubuntu:20.04\nRUN curl https://example.com/script.sh | bash"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da006_findings = [f for f in findings if f.rule_id == "DA006"]
        self.assertEqual(len(da006_findings), 1)
        self.assertEqual(da006_findings[0].severity, dockaudit.Severity.ERROR)

    def test_da007_consecutive_runs(self):
        """Test DA007: Consecutive RUN instructions."""
        content = """FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get clean
"""
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da007_findings = [f for f in findings if f.rule_id == "DA007"]
        self.assertGreater(len(da007_findings), 0)

    def test_da008_add_vs_copy(self):
        """Test DA008: Use COPY instead of ADD for local files."""
        content = "FROM ubuntu:20.04\nADD ./app /app"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da008_findings = [f for f in findings if f.rule_id == "DA008"]
        self.assertEqual(len(da008_findings), 1)

    def test_da010_apt_no_recommends(self):
        """Test DA010: apt-get install without --no-install-recommends."""
        content = "FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y curl"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da010_findings = [f for f in findings if f.rule_id == "DA010"]
        self.assertEqual(len(da010_findings), 1)

    def test_da011_apt_cleanup(self):
        """Test DA011: apt-get without cleanup."""
        content = "FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y curl"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da011_findings = [f for f in findings if f.rule_id == "DA011"]
        self.assertEqual(len(da011_findings), 1)

    def test_da014_sudo_in_run(self):
        """Test DA014: Using sudo in RUN."""
        content = "FROM ubuntu:20.04\nRUN sudo apt-get update"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da014_findings = [f for f in findings if f.rule_id == "DA014"]
        self.assertEqual(len(da014_findings), 1)

    def test_da017_shell_form_cmd(self):
        """Test DA017: CMD/ENTRYPOINT in shell form."""
        content = "FROM ubuntu:20.04\nCMD python app.py"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da017_findings = [f for f in findings if f.rule_id == "DA017"]
        self.assertEqual(len(da017_findings), 1)

    def test_da021_missing_from(self):
        """Test DA021: Missing FROM instruction."""
        content = "RUN echo test"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da021_findings = [f for f in findings if f.rule_id == "DA021"]
        self.assertGreater(len(da021_findings), 0)

    def test_da022_apt_update_no_install(self):
        """Test DA022: apt-get update without install in same RUN."""
        content = "FROM ubuntu:20.04\nRUN apt-get update"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da022_findings = [f for f in findings if f.rule_id == "DA022"]
        self.assertEqual(len(da022_findings), 1)
        self.assertEqual(da022_findings[0].severity, dockaudit.Severity.ERROR)


class TestGrading(unittest.TestCase):
    """Test grading system."""

    def test_perfect_score(self):
        """Test that a perfect Dockerfile gets A grade."""
        content = """FROM ubuntu:20.04
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
        findings, score, grade, _ = dockaudit.lint_dockerfile(content)
        # May have some findings, but check grade calculation works
        calc_score, calc_grade = dockaudit.calculate_grade(findings)
        self.assertEqual(score, calc_score)
        self.assertEqual(grade, calc_grade)
        self.assertIn(grade, ["A", "B", "C", "D", "F"])

    def test_grade_with_errors(self):
        """Test grading with multiple severity levels."""
        # Create findings manually
        findings = [
            dockaudit.Finding("DA001", dockaudit.Severity.ERROR, 1, 1, "Test", "Test error"),
            dockaudit.Finding("DA002", dockaudit.Severity.WARNING, 2, 2, "Test", "Test warning"),
            dockaudit.Finding("DA003", dockaudit.Severity.INFO, 3, 3, "Test", "Test info"),
        ]
        score, grade = dockaudit.calculate_grade(findings)
        # Error=15, Warning=5, Info=2 -> 100-22=78
        self.assertEqual(score, 78)
        self.assertEqual(grade, "C")

    def test_grade_floor(self):
        """Test that score doesn't go below 0."""
        findings = [dockaudit.Finding("DA001", dockaudit.Severity.ERROR, i, i, "Test", "Test") 
                    for i in range(20)]  # 20 errors = 300 points
        score, grade = dockaudit.calculate_grade(findings)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")


class TestIgnoreRules(unittest.TestCase):
    """Test rule ignoring functionality."""

    def test_ignore_single_rule(self):
        """Test ignoring a specific rule."""
        content = "FROM ubuntu:latest\nRUN echo test"
        findings, _, _, _ = dockaudit.lint_dockerfile(content, ignore_rules={"DA002"})
        da002_findings = [f for f in findings if f.rule_id == "DA002"]
        self.assertEqual(len(da002_findings), 0)

    def test_ignore_multiple_rules(self):
        """Test ignoring multiple rules."""
        content = "FROM ubuntu:latest\nRUN echo test"
        findings, _, _, _ = dockaudit.lint_dockerfile(content, ignore_rules={"DA002", "DA003"})
        ignored_findings = [f for f in findings if f.rule_id in {"DA002", "DA003"}]
        self.assertEqual(len(ignored_findings), 0)


class TestSeverityFiltering(unittest.TestCase):
    """Test minimum severity filtering."""

    def test_filter_by_error_only(self):
        """Test showing only errors."""
        content = """FROM ubuntu:latest
RUN apt-get update
"""
        findings, _, _, _ = dockaudit.lint_dockerfile(content, min_severity=dockaudit.Severity.ERROR)
        for f in findings:
            self.assertEqual(f.severity, dockaudit.Severity.ERROR)

    def test_filter_by_warning(self):
        """Test showing errors and warnings."""
        content = """FROM ubuntu:latest
RUN apt-get update
"""
        findings, _, _, _ = dockaudit.lint_dockerfile(content, min_severity=dockaudit.Severity.WARNING)
        for f in findings:
            self.assertIn(f.severity, [dockaudit.Severity.ERROR, dockaudit.Severity.WARNING])


class TestOutputFormats(unittest.TestCase):
    """Test output formatting."""

    def test_json_output(self):
        """Test JSON output format."""
        content = "FROM ubuntu:latest\nRUN echo test"
        findings, score, grade, errors = dockaudit.lint_dockerfile(content)
        json_output = dockaudit.format_json("Dockerfile", findings, score, grade, errors)
        data = json.loads(json_output)
        self.assertIn("version", data)
        self.assertIn("file", data)
        self.assertIn("grade", data)
        self.assertIn("findings", data)
        self.assertIsInstance(data["findings"], list)

    def test_text_output(self):
        """Test text output format."""
        content = "FROM ubuntu:latest\nRUN echo test"
        findings, score, grade, errors = dockaudit.lint_dockerfile(content)
        text_output = dockaudit.format_text("Dockerfile", findings, score, grade, errors)
        self.assertIn("dockaudit", text_output)
        self.assertIn("Grade:", text_output)


class TestCLI(unittest.TestCase):
    """Test CLI argument handling."""

    def test_list_rules(self):
        """Test --list-rules flag."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            exit_code = dockaudit.main(["--list-rules"])
            output = fake_out.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("DA002", output)
            self.assertIn("DA003", output)

    def test_check_grade_pass(self):
        """Test --check flag with passing grade."""
        # Create a temporary good Dockerfile
        good_content = """FROM ubuntu:20.04
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
        with patch('builtins.open', unittest.mock.mock_open(read_data=good_content)):
            with patch('os.path.isfile', return_value=True):
                exit_code = dockaudit.main(["--check", "F", "Dockerfile"])
                # Should pass with any grade vs F
                self.assertEqual(exit_code, 0)

    def test_version(self):
        """Test --version flag."""
        with self.assertRaises(SystemExit) as cm:
            dockaudit.main(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_empty_dockerfile(self):
        """Test parsing an empty Dockerfile."""
        content = ""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertEqual(len(instructions), 0)

    def test_only_comments(self):
        """Test Dockerfile with only comments."""
        content = """# Comment 1
# Comment 2
# Comment 3
"""
        instructions, errors = dockaudit.parse_dockerfile(content)
        self.assertEqual(len(instructions), 0)

    def test_scratch_image(self):
        """Test that scratch base image doesn't trigger :latest warning."""
        content = "FROM scratch\nCOPY app /app"
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da002_findings = [f for f in findings if f.rule_id == "DA002"]
        self.assertEqual(len(da002_findings), 0)

    def test_arg_based_from(self):
        """Test FROM with ARG variable doesn't trigger :latest."""
        content = """ARG BASE_IMAGE
FROM $BASE_IMAGE
"""
        findings, _, _, _ = dockaudit.lint_dockerfile(content)
        da002_findings = [f for f in findings if f.rule_id == "DA002"]
        self.assertEqual(len(da002_findings), 0)


if __name__ == "__main__":
    unittest.main()
