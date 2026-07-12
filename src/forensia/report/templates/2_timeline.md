---
type: report-section-template
title: Activity Timeline
description: Time-normalized chronology, source coverage, log integrity, and incident phases.
tags: [incident-response, timeline, chronology, log-integrity]
timestamp: 2026-07-12
instructions: |
  Reconstruct the incident in chronological order using normalized timestamps.
  Make the timezone and evidence coverage explicit. Separate observed events from
  inferred transitions, preserve conflicting timestamps, and explain gaps that
  could change the interpretation of sequence or duration.
---
# Activity Timeline

## Time Basis and Coverage
<!-- mode: narrative; State the reporting timezone, clock assumptions, covered period, source coverage, and any timestamp normalization or correlation limitations. -->

## Log Integrity
<!-- mode: narrative; Evaluate log completeness, retention, clearing, collection gaps, and integrity issues that affect interpretation of the timeline. -->

## Phase Summary
<!-- mode: table; builder: timeline_phase_summary -->

## Chronological Events
<!-- mode: table; builder: timeline_chronological -->
