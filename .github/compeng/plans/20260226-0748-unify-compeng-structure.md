---
status: approved
priority: high
tags: [compeng, repo-hygiene, workflow, vscode]
owner: Rix
created: 2026-02-26 07:48 Europe/Budapest
estimated_hours: 1-2
issue: inline
---

# Plan — Unify CompEng structure under `.github/compeng/` (remove repo-root `compeng/`)

## 0) Issue (inline)

### Problem / context
A `rixbeck/obsidian-oclaw-chat` repóban **két párhuzamos CompEng fa** van:

- `repo-root/compeng/…`
- `repo-root/.github/compeng/…`

Ez divergens állapotot okoz (duplikált/eltérő plan/run/review fájlok, hivatkozások szétesnek), és nehezíti a fejlesztés folytatását VS Code / Copilot dev környezetben, mert nem egyértelmű, melyik a kanonikus projekt-állapot.

### Proposal / solution
Tegyük a `.github/compeng/` mappát az **egyetlen kanonikus** CompEng gyökérré ebben a repóban:

- a teljes `repo-root/compeng/` tartalmát **mozgatni/összefésülni** `.github/compeng/` alá
- duplikátumok esetén **egyetlen példány marad**, a másik archiválva vagy átnevezve
- frissítsük a hivatkozásokat (README-k, frontmatter `plan/run` linkek), hogy minden `.github/compeng/...`-ra mutasson
- adjunk egy rövid `.github/compeng/WORKFLOW.md` vagy `README.md` kiegészítést, ami leírja az egységesített szabályt

### Benefits
- Egyértelmű, követhető CompEng állapot a repón belül.
- Fejlesztés könnyen folytatható VS Code/Copilot környezetben.

### Risks
- Hivatkozások törése (régi `compeng/...` pathok).
- Véletlen adatvesztés, ha merge során duplikátumot rosszul kezelünk.

## 1) Tanulságok / releváns szabályok

- A CompEng állapot legyen **egyértelmű SSOT**, különben a workflow “szétcsúszik”.
- Mozgatás előtt és után legyen ellenőrzés (diff, lista, linkek) — a „csendes törés” a legrosszabb.

## 2) Scope

### In-scope
- `compeng/{plans,runs,reviews,issues,knowledge}/` tartalom átköltöztetése `.github/compeng/` alá (ahol értelmezett)
- duplikált fájlok kezelése
- linkek és dokumentáció igazítása

### Out-of-scope
- OpenClaw runtime / gateway konfiguráció (ez repo-szerkezeti higiénia)
- korábbi, már lezárt workflowk átírása a szükséges minimumon túl

## 3) Current state discovery (GATE)

1) Készítsünk teljes listát mindkét fáról:
   - `find compeng -type f | sort`
   - `find .github/compeng -type f | sort`
2) Azonosítsuk a duplikátumokat:
   - azonos fájlnév (pl. ugyanaz a plan ID)
   - tartalmi egyezés / eltérés (hash vagy diff)
3) Döntsük el a merge szabályt:
   - ha ugyanaz a fájl két helyen és azonos → egyik törölhető
   - ha eltér → az egyik legyen kanonikus (általában a frissebb/aktuális), a másik menjen `archive/` alá vagy `*-migrated-from-root.md` suffix-szel

## 4) Target structure

A repóban a CompEng gyökér **mindig**:

- `.github/compeng/`
  - `plans/`
  - `runs/`
  - `reviews/`
  - `issues/` (ha használjuk)
  - `knowledge/` (ha a projektnek van saját)
  - `WORKFLOW.md` (SSOT + naming + gates röviden)

A `repo-root/compeng/` **nem maradhat**.

## 5) Migration steps

1) **Safety backup (git)**
   - Győződjünk meg róla, hogy working tree clean
   - hozzunk létre egy migrációs branch-et (pl. `dev-terse` alatt is jó)

2) **Move/merge**
   - Mozgassuk át a `compeng/plans/*` → `.github/compeng/plans/`
   - Mozgassuk át a `compeng/runs/*` → `.github/compeng/runs/`
   - Mozgassuk át a `compeng/reviews/*` → `.github/compeng/reviews/`
   - `compeng/issues/*` és `compeng/knowledge/*`:
     - ha a projektben aktívan használjuk, akkor `.github/compeng/issues|knowledge` alá
     - ha üres/.gitkeep, migrálható egyszerűen

3) **Dedup + archive strategy**
   - Hozzunk létre `.github/compeng/archive/` mappát csak migrációs célra (ha kell)
   - Duplikátumok esetén:
     - keep: a hivatkozott/aktuális példány `.github/compeng/...`
     - move: a másik `archive/` alá rövid megjegyzéssel a file elején ("migrated from repo-root/compeng")

4) **Update references**
   - Repo `README.md`, `channel-plugin/README.md`, `obsidian-plugin/README.md`: minden `compeng/...` link → `.github/compeng/...`
   - Review frontmatter (ahol `plan:`/`run:`) frissítése a new pathokra

5) **Remove old tree**
   - Ha minden átment: töröljük a `repo-root/compeng/` mappát

6) **Validation**
   - `find compeng -type f` → üres / nincs ilyen
   - `.github/compeng` alatt minden file elérhető
   - `rg -n "\bcompeng/"` a repo rootban → ne maradjon régi hivatkozás

## 6) Test plan

- Strukturális:
  - `git status` clean, csak a várt moved/edited fájlok
  - `git diff --stat` értelmes
- Hivatkozás ellenőrzés:
  - `rg -n "\.github/compeng" README-kben
  - `rg -n "\bcompeng/"` (régi pathok kiszűrése)

## 7) Acceptance criteria

- AC1: A repóban **nincs** `repo-root/compeng/` (eltávolítva)
- AC2: Minden projekt CompEng artifact a `.github/compeng/{plans,runs,reviews,...}` alatt van
- AC3: Nincs törött belső hivatkozás (README-k + frontmatter linkek frissítve)
- AC4: A projekt CompEng állapota VS Code/Copilot környezetben egyértelműen követhető

## 8) Rollback

- A migráció egy dedikált branch-en történik.
- Rollback = branch eldobása / reset a migráció előtti commitra.
