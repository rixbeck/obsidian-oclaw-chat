# Compound Engineering Workflow

This project uses the Compound Engineering workflow for structured, learning-oriented development.

## Overview

Four-phase structured development with learning loop:

**PLAN** → **WORK** → **REVIEW** → **COMPOUND** → repeat

Each phase has a specialized custom agent:
- `@plan` - Research and create implementation plan
- `@work` - Execute plan with detailed logging
- `@review` - Spawn 6 reviewers, synthesize findings
- `@compound` - Distill learnings into knowledge artifacts

## Critical: Learning Loop

**Before PLAN phase:** ALWAYS read ALL files in `.github/compeng/knowledge/*` folders:
- `.github/compeng/knowledge/decisions/` - Architectural decisions (ADRs)
- `.github/compeng/knowledge/checklists/` - Domain-specific review items
- `.github/compeng/knowledge/gotchas/` - Mistakes and their prevention
- `.github/compeng/knowledge/patterns/` - Best practices and patterns

Apply learnings from knowledge base to avoid repeating mistakes. Reference applied knowledge in plans.

## FSM Gating Rules

**Cannot skip phases:**
- WORK phase requires Plan artifact in `.github/compeng/plans/`
- REVIEW phase requires Run log in `.github/compeng/runs/`
- COMPOUND phase requires Review with no Must-fix items
- If Review has Must-fix items → return to WORK

## Artifact Conventions

**Naming:** `YYYYMMDD-HHMM-<slug>.md`

**Locations:**
- Plans → `.github/compeng/plans/YYYYMMDD-HHMM-<slug>.md`
- Runs → `.github/compeng/runs/YYYYMMDD-HHMM-<slug>.md`
- Reviews → `.github/compeng/reviews/YYYYMMDD-HHMM-<slug>.md`
- Knowledge → `.github/compeng/knowledge/{decisions,checklists,gotchas,patterns}/`

## Workflow Usage

1. **Start with @plan**: Research, read `.github/compeng/knowledge/*`, create detailed plan
2. **Handoff to @work**: Execute plan in small traceable steps
3. **Handoff to @review**: Parallel review by 6 specialists
4. **If clean → @compound**: Capture learnings for future iterations
5. **If issues → @work**: Fix Must-fix items, then re-review

## Knowledge Structure

**ADR (Architectural Decision Record):**
- Context → Decision → Consequences → Alternatives → Follow-ups
- Location: `.github/compeng/knowledge/decisions/ADR-YYYYMMDD-<slug>.md`

**Gotcha (Mistake/Surprise):**
- What happened → Root cause → Prevention → References
- Location: `.github/compeng/knowledge/gotchas/<domain>.md`

**Pattern (Best Practice):**
- When to use → Implementation → Best practices → Examples
- Location: `.github/compeng/knowledge/patterns/<domain>.md`

**Checklist (Review Items):**
- Item → Rationale → Incident link (if applicable)
- Location: `.github/compeng/knowledge/checklists/<domain>.md`

## Review Charters

The `@review` agent spawns 6 specialized reviewers:
1. **Security** - Credential leaks, injection, path traversal
2. **Performance** - O(n²) algorithms, memory usage, I/O efficiency
3. **API Contracts** - Breaking changes, versioning, backward compatibility
4. **Maintainability** - Code readability, duplication, modularity
5. **Tests** - Coverage, missing tests, edge cases
6. **Overengineering** - YAGNI violations, unnecessary complexity

Each reviewer uses a charter from `.github/skills/compeng-review/charters/`.

## Continuous Improvement

Every iteration compounds knowledge:
- Phase 1: Implementation (PLAN → WORK → REVIEW)
- Phase 2: Learning (COMPOUND captures insights)
- Phase 3: Application (Next PLAN applies captured knowledge)

The more iterations, the smarter the system becomes.
