# Product / Native UX — The Intelligence Archive

- Created / updated: 2026-10-31 JST
- Status: vision, not implemented

## 1. Identity

Product name: **Eidoron**. Design target: a restrained intelligence archive, not a neon 'hacker console'. Visual vocabulary: obsidian, graphite, desaturated steel, fine rules, precise typography, intentional motion, paper dossiers, classified indexing. Accessible in light/dark modes and reduced motion.

The emotional metaphor is **unseal → inspect → re-seal**, not 'I became anonymous'. Cinematic UI must not imply unverified security.

## 2. Core flows (Vault mode)

1. Onboard: explain protection and leakage boundaries, choose storage, create strong passphrase, display recovery limitations.
2. Create vault: local key derivation, first encrypted object commit, no server account required except provider's own authentication.
3. Unlock: locally derive key, authenticate index, render files; avoid plaintext preview before verification.
4. Import: preview file source privacy, encrypt locally, upload asynchronously with retry state.
5. Explore: dossiers / folders / timeline, with consistent native viewer for photo/PDF/text.
6. Lock: clear sensitive UI and in-memory key material best-effort; explicitly distinguish local lock from cloud deletion.
7. Recovery/export: verified export, secure destination guidance, erase temp files best-effort.

Native device protections: app background snapshot redaction, screenshot warnings where APIs allow, share-sheet safety, sanitized push notifications, accessibility, crash-log redaction. Hardware-backed keystore protects stored wrapping material where possible, not master password entropy.

## 3. Concept feature names

- **Archive Seal** — lock/unlock with understated mechanical animation.
- **Dossier View** — rich internal PDF/image/text preview, clear metadata.
- **Blind Index** — user-facing searchable encrypted index; search is device-local after unlock.
- **Dead Drop (future)** — encrypted person-to-person transfer with verified recipient identity; no promise remote deletion.
- **Exposure Radar** — honest cloud/device metadata leakage checklist, not a fictional quantitative security score.
- **Phantom Access (research)** — password-defined spaces; hidden-state UI is not proof of deniability.
- **Emergency Seal** — immediate local lock and best-effort memory wipe; no fake self-destruction.
- **Chain of Custody (optional)** — integrity history with separate privacy analysis; logs themselves can undermine secrecy.

## 4. Hidden access design constraints

No secret-folder toggle on ordinary view; no device notification with secret names; no 'wrong password but another space exists' response. Hidden onboarding, recovery, biometric convenience and audit records each can leave traces. Evaluate these *before* shipping any hidden view.

An elaborate interface must never expose a secret access mode through an identifiable icon, alternate URL scheme, notification, or keyboard pattern in the ordinary view. Hidden UI is a separate usability research workstream with mandatory consent, recovery and safety review.

## 5. Native implementation

SwiftUI for iOS (macOS later); Jetpack Compose/Kotlin for Android. Portable Rust engine via stable C ABI/UniFFI candidate, checked on real devices. No Expo as primary architecture. Prefer high fidelity in native file viewer over embedding web UI. iOS File Provider and Android Storage Access Framework are optional integrations after plaintext boundary reviews.

## 6. Accessibility / transparency

- VoiceOver/TalkBack coverage, Dynamic Type, large touch targets and high-contrast mode.
- Plain labels alongside metaphorical labels ('Seal / Lock now').
- Always display *real* sync state (local-only, queued, synced, conflict, restore needed).
- Explicit opt-in for any telemetry; never send filenames or sensitive operation traces to an analytics server.
- Product documentation must distinguish baseline file confidentiality from experimental hiding of existence.
