---
name: compeng-review
description: Perform specialized code review using one of 6 review charters (security, performance, API contracts, maintainability, tests, overengineering)
---

# Compound Engineering Review Skill

This skill provides specialized review charters for parallel code review in the Compound Engineering workflow.

## Overview

The review phase uses 6 specialized reviewers, each with their own charter:

1. **Security** - Credential leaks, injection vulnerabilities, path traversal
2. **Performance** - Algorithm complexity, memory usage, I/O efficiency
3. **API Contracts** - Breaking changes, versioning, backward compatibility
4. **Maintainability** - Code readability, duplication, modularity
5. **Tests** - Coverage, missing tests, edge cases
6. **Overengineering** - YAGNI violations, unnecessary complexity

## Charters

Each charter is a specialized reviewer role with specific focus areas:

- [Security Charter](./charters/security.md)
- [Performance Charter](./charters/performance.md)
- [API Contracts Charter](./charters/api-contracts.md)
- [Maintainability Charter](./charters/maintainability.md)
- [Tests Charter](./charters/tests.md)
- [Overengineering Charter](./charters/overengineering.md)

## Usage

When the `@review` agent invokes this skill, it spawns 6 sub-agents, each with a charter:

```
You are a [ROLE] reviewer. Your charter:

[Load charter from ./charters/<charter>.md]

Review these changes:
- Files changed: [list]
- Plan context: [plan artifact]
- Run context: [run artifact]

Categorize findings as:
- Must-fix: Critical issues that block approval
- Should-fix: Important improvements
- Nice-to-have: Optional suggestions

Report structured findings.
```

## Reporting Format

Each reviewer reports findings in this structure:

**Must-fix Issues:**
- Issue title
- Location (file:line)
- Description and impact
- Recommended fix

**Should-fix Issues:**
- Same structure, medium priority

**Nice-to-have Suggestions:**
- Brief recommendations

## Resources

This skill includes:
- `SKILL.md` - This file
- `charters/` - 6 specialized charter files

The charters are concise (4-5 lines each) to minimize context usage while providing clear focus.

## Progressive Loading

- **Level 1:** Skill discovery (name + description)
- **Level 2:** When review is needed, this SKILL.md loads
- **Level 3:** Individual charters load only when spawning sub-reviewers

This keeps context efficient while providing specialized capabilities.
