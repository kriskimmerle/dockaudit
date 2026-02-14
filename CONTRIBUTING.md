# Contributing to dockaudit

Thank you for considering contributing to dockaudit! This document provides guidelines for contributing.

## How to Contribute

### Reporting Issues

- Use the GitHub issue tracker
- Include the version of dockaudit (`dockaudit --version`)
- Provide a minimal Dockerfile that reproduces the issue
- Describe expected vs actual behavior

### Suggesting New Rules

When proposing a new lint rule:

1. Explain the security/quality issue it detects
2. Provide examples of problematic Dockerfiles
3. Suggest the severity level (error/warning/info)
4. Include a fix recommendation

### Code Contributions

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix
3. **Make your changes**:
   - Follow existing code style
   - Add tests for new functionality
   - Update README.md if adding user-facing features
4. **Test your changes**:
   ```bash
   python3 test_dockaudit.py
   ./dockaudit.py test/fixtures/*.Dockerfile
   ```
5. **Commit** with a clear message
6. **Push** to your fork
7. **Open a pull request**

## Development Setup

dockaudit has zero dependencies (stdlib only), so setup is simple:

```bash
git clone https://github.com/kriskimmerle/dockaudit.git
cd dockaudit
python3 test_dockaudit.py  # Run tests
```

## Adding a New Rule

To add a new lint rule:

1. Add the rule function in `dockaudit.py` using the `@rule` decorator:
   ```python
   @rule("DA028", Severity.WARNING, "Brief title")
   def check_something(instructions, stages, findings, content):
       for inst in instructions:
           if inst.keyword == "RUN":
               # Your detection logic
               findings.append(Finding(
                   rule_id="DA028",
                   severity=Severity.WARNING,
                   line=inst.line,
                   end_line=inst.end_line,
                   title="Brief title",
                   message="Detailed explanation",
                   fix="How to fix it",
               ))
   ```

2. Add tests in `test_dockaudit.py`:
   ```python
   def test_da028_something(self):
       """Test DA028: Brief description."""
       content = "FROM ubuntu:20.04\nRUN problematic-command"
       findings, _, _, _ = dockaudit.lint_dockerfile(content)
       da028_findings = [f for f in findings if f.rule_id == "DA028"]
       self.assertEqual(len(da028_findings), 1)
   ```

3. Run tests to verify

## Code Style

- Use Python 3.7+ features where helpful
- Type hints preferred (using `from __future__ import annotations`)
- Docstrings for public functions
- Keep it readable - clarity over cleverness
- No external dependencies (stdlib only)

## Testing

- All new rules must have test coverage
- Test both positive (catches the issue) and negative (doesn't false-positive) cases
- Run `python3 test_dockaudit.py` before submitting

## Pull Request Guidelines

- Keep changes focused - one feature/fix per PR
- Update README.md if adding user-visible features
- Add your name to contributors if you'd like
- Be patient - reviews may take a few days

## Questions?

Open an issue with the "question" label or reach out to the maintainer.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
