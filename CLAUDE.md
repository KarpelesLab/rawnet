# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands
- Build: `make all` or `go build -v`
- Install dependencies: `make deps` or `go get -v -t .`
- Test: `make test` or `go test -v`
- Run a single test: `go test -v -run=TestName`

## Code Style
- Use goimports for import formatting: `goimports -w -l .`
- Follow standard Go naming conventions (CamelCase for exported, camelCase for internal)
- Use interfaces for abstractions (see L2Device, L3Device, etc.)
- Error handling: Always check returned errors and propagate them up
- Types: Use Go's strong typing system and define clear interfaces
- Keep functions small and focused on a single responsibility
- Use Go modules for dependency management
- Use consistent naming for protocol handlers
- Document all exported functions and types with comments
- Use proper error wrapping with context when appropriate