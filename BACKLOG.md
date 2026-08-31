# Backlog

- [ ] Watch for the daily refresh (`updateInterval: 86400`) in the log before
      trusting the sync loop — one confirmed conditional request is not a
      cadence.
- [ ] Certificate renewal is manual: `local_ca` issues for a year and nothing
      renews it. `status` warns 30 days out; decide whether that is enough or
      whether the role should reissue when the remaining validity gets short.
- [ ] Serve more than one rule group, once `LittleSnitchConfig` has the
      themed files it plans (`dev-tools`, `apple-services`, …). Nothing in
      the server needs changing for that — it already serves the directory —
      but the subscription list in Little Snitch does.
- [ ] Consider whether `status` should also report the subscription side:
      the log knows when Little Snitch last fetched, which is the question
      "is my subscription alive" actually asks.
- [ ] The cask publish has never actually run: v0.1.0 and v0.2.0 both got a
      401 (no `HOMEBREW_TAP_TOKEN`) and the cask was written by hand.
      The secret is set now — the next release is what proves it, and if it
      fails again the tap holds a hand-written file that must be replaced
      rather than edited.
