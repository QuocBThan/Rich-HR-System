# Product

## Register

product

## Users

HR managers at Rich Payment Solutions — one or two people processing dozens of attendance records daily. They move fast, know what they're looking for, and want data that's immediately scannable. Secondary users are employees checking their own records via the portal (read-only, occasional use, less technical).

The primary user's mindset: decisive, time-pressured, needs to trust the numbers at a glance. Not exploring — executing.

## Product Purpose

An internal HR operations tool for importing, reviewing, and reporting on employee attendance data exported from Lark. Core workflows: upload → auto-process → review flagged records → generate payroll-period reports → export. Employees log in to view only their own attendance history.

Success looks like: HR finishes the monthly payroll cycle with no missed edge cases and zero time spent hunting through raw exports.

## Brand Personality

Efficient. Precise. No-nonsense.

Voice: terse and direct, like a good internal tool should be. No decorative copy, no welcome messages, no fluff. Every label earns its space.

The product should feel like it was built by engineers who actually use it — dense information, fast interactions, immediate feedback on actions.

## References

Retool / internal tooling aesthetic: grid-heavy, data-first, utility over beauty. The tool respects the user's intelligence and doesn't hand-hold. Information density is a feature, not a bug.

## Anti-references

- Generic Bootstrap: no default table-on-table look with no visual hierarchy, no identity beyond blue buttons
- Consumer-app cute: no rounded bubbles, emoji-heavy labels, or friendly-app softness
- Enterprise bloat: no nested accordions, modal-on-modal, or overcomplicated navigation

## Design Principles

1. **Data first, chrome last.** The table, the numbers, the status — those are the product. Sidebars, headers, and controls exist to serve the data, not compete with it.
2. **Every state is explicit.** OK, Late, Missing, Overtime, Manual — each status is visually unambiguous at a glance, even in a 40-row table.
3. **Actions are irreversible, so make them feel weighty.** Destructive or final actions (approve, mark done) get clear visual weight and confirmation. Browsing is frictionless; committing is deliberate.
4. **Dense, not cramped.** Maximize information per screen-inch without crossing into unreadable. Padding is earned by importance.
5. **Vietnamese-first.** All UI copy, labels, and interactions are designed for Vietnamese-speaking HR staff. Abbreviations and conventions follow local HR practice (kỳ 1/kỳ 2, đi trễ, tăng ca).

## Accessibility & Inclusion

WCAG AA target. Body text must hit ≥4.5:1 contrast against background at all times. Status badges must never rely on color alone — pair color with a text label or icon. Reduced-motion: any transitions added later must respect `prefers-reduced-motion`. Primary users are desktop — responsive is a nice-to-have, not a requirement.
