# Contributing to OpenClaw Prompt Antivirus

Thanks for taking the time to contribute! 🛡️

## Getting started

```bash
git clone https://github.com/QinpanWan/openclaw-prompt-antivirus.git
cd openclaw-prompt-antivirus
pip install -e .
```

## Running tests

```bash
python -m unittest discover -s tests -v
```

## How to contribute

1. **Fork** the repo and create a branch: `fix/issue-<n>` or `feat/<short-name>`.
2. Make a **small, focused** change. Don't bundle unrelated refactors.
3. Add or update **tests** for your change so CI stays green.
4. Make sure `python -m unittest discover -s tests -v` passes.
5. Open a PR with:
   - What problem this solves.
   - Why this change was made.
   - Evidence (test output / before-after).

## Style

- Keep signatures English-centric but **additive** — tighten the regex, don't break existing detections.
- Add new rules to `prompt_antivirus/signatures.py` as `(regex, severity, category, replacement)`.
- Docs: update the README if you change behavior.

## Code of conduct

Be welcoming. No harassment, no spam, no star-farming.

## License

By contributing, you agree your contributions are under the [MIT License](LICENSE).
