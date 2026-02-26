---
type: plan
status: approved
created: 2026-02-26T23:59:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/chat.ts
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/styles.css
  - obsidian-plugin/src/*.test.ts
---

# Plan — Auto-dismiss system notifications in chat UI (fade-out + remove)

## Problem
System/status messages (reconnect, errors) render as red notification boxes that remain in the chat history, cluttering the UI.

## Goal
Auto-dismiss transient system messages:
- after **5 seconds** start **fade-out** animation
- then remove from DOM AND from ChatManager message list

## Rules
- Apply only to `role: 'system'` messages **except** session divider (`kind: 'session-divider'`).

## Implementation
1) `ChatManager`
- Add `removeMessage(id: string): void` that removes by id and triggers `onUpdate` with the new list.

2) `OpenClawChatView`
- In `_appendMessage`, when appending a system message element (non-divider):
  - `setTimeout` after 5s to add CSS class (`oclaw-fade-out`)
  - after transition, call `chatManager.removeMessage(msg.id)`

3) CSS
- Add `.oclaw-fade-out` transition (opacity + transform).

4) Tests
- Add minimal `chat.test.ts` for `removeMessage`.

## Gates
- typecheck
- tests
- build
