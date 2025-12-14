# Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/andrew/sbom.

## Getting Started

1. Fork the repository
2. Clone your fork and set up the development environment:

```bash
git clone https://github.com/YOUR_USERNAME/sbom.git
cd sbom
bin/setup
git submodule update --init --recursive
```

3. Run the tests to make sure everything works:

```bash
bundle exec rake test
```

## Making Changes

1. Create a feature branch from `main`
2. Make your changes
3. Add tests for any new functionality
4. Ensure all tests pass
5. Submit a pull request

## Code Style

- Follow existing code conventions
- Keep commits focused and atomic
- Write clear commit messages

## Running Tests

```bash
bundle exec rake test
```

## Reporting Bugs

When reporting bugs, please include:
- Ruby version
- Steps to reproduce
- Expected vs actual behavior
- Sample SBOM files if relevant (sanitized of any sensitive data)
