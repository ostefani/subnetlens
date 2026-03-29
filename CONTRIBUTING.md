# Contribution Guidelines

## Submitting a PR

1. Fork the repository and create a branch from `main`
2. Follow the branch naming and commit conventions above
3. Open a pull request with a clear description of the change
4. PRs with focused, single-purpose changes are reviewed faster

## Branch Names

Use the following prefixes:

- `feature/` — new features
- `fix/` — bug fixes
- `doc/` — documentation changes

Examples:

- `feature/add-login`
- `fix/null-user-id`
- `doc/update-readme`

## Commit Messages

Use conventional commit labels:

- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation

Write the subject line as an imperative:

- `feat: add login form`
- `fix: handle null user ID`
- `docs: update README`

Rules:

- Keep commits short and clear
- Use one change per commit when possible
- Prefer present tense and imperative mood

## Naming Conventions in Go

Use standard Go naming rules:

- Exported names use `PascalCase`
- Unexported names use `camelCase`
- Keep names short and descriptive
- Use consistent acronym casing: `ID`, `URL`, `HTTP`
- Avoid redundant names like `user.UserID` when `user.ID` is enough

Examples:

- `userID`
- `httpClient`
- `ParseConfig`
- `NewServer`

## General

- Follow the existing code style
- Keep changes focused
- Write clear code and documentation
