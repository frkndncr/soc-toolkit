# Contributing to SOC Toolkit 🛡️

Thank you for your interest in contributing to **SOC Toolkit**! We welcome contributions from cybersecurity researchers, SOC analysts, threat hunters, and developers worldwide.

---

## 📋 How Can I Contribute?

### 1. Reporting Bugs
- Search existing [GitHub Issues](https://github.com/frkndncr/soc-toolkit/issues) to avoid duplicates.
- If you find a new bug, open an issue using the **Bug Report** template.
- Include Python version, OS details, error traceback, and step-by-step reproduction steps.

### 2. Suggesting Enhancements & Features
- Open an issue using the **Feature Request** template.
- Clearly describe the feature, the problem it solves, and why it benefits SOC personnel.

### 3. Submitting Pull Requests (PRs)
1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/soc-toolkit.git
   cd soc-toolkit
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. Implement your changes and ensure coding standards:
   - Preserving UTF-8 stdio compatibility across Windows, Linux, and macOS.
   - Adding comprehensive unit test coverage in `tests/`.
5. Run the offline test runner to ensure **100% test pass rate**:
   ```bash
   python tests/run_tests.py
   ```
6. Commit your changes:
   ```bash
   git commit -m "feat: Add new threat intelligence provider"
   ```
7. Push to your branch and open a Pull Request against `main`.

---

## 🧪 Development & Testing Rules

- All core functions **MUST** have corresponding unit tests in `tests/`.
- Unit tests **MUST NOT** rely on live external network lookups during CI runs. Use synthetic `IOCReport` fixtures or mock providers.
- Maintain compatibility with **Python 3.8, 3.9, 3.10, 3.11, 3.12, and 3.13**.

---

## 📜 Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
