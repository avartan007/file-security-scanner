# Contributing

## Development Setup

```bash
git clone https://github.com/yourusername/file-security-scanner.git
cd file-security-scanner
make dev
```

## Running Tests

```bash
make test
```

## Code Quality

```bash
make lint
```

## Submitting Changes

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run tests: `make test`
4. Run linter: `make lint`
5. Commit: `git commit -am 'Add feature'`
6. Push: `git push origin feature/your-feature`
7. Submit a pull request

## Code Style

- Use PEP 8
- Black for formatting: `black src/`
- isort for imports: `isort src/`
- Max line length: 100 characters

## Issues

Found a bug? Please open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Python version
