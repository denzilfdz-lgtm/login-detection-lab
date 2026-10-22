# Login Detection and Investigation Lab

A small, standard-library-only Python project for exploring failed-login detection and basic alert triage from synthetic authentication logs. It is an educational portfolio project, not a production security product.

## Features

- Count failed logins by username or source IP in the early scripts.
- Detect a threshold of failed logins from the same source IP inside a rolling time window.
- Sort timestamped events so out-of-order input does not change the primary detector's result.
- Score successful logins that follow recent failures and explain why they were flagged.
- Write a plain-text investigation report.
- Run unit tests with Python's built-in `unittest`.

### Detection rules

- `login_detector_v2.py` raises one alert per source IP when it finds at least 3 failed logins inside a 120-second rolling window.
- `login_investigator.py` evaluates each successful login against failures from that source IP in the previous 10 minutes. It adds 2 points for at least 2 recent failures, 2 points when a success follows any recent failure, and 1 point when the event time is before 06:00 or at/after 22:00. It reports events with a score of 3 or higher.

The thresholds and time windows are constants in the source code.

## Requirements

- Python 3.9 or newer
- No third-party packages

## Quick start

Open Ubuntu WSL and run:

```bash
cd ~/cyberlab
python3 --version
python3 login_detector_v2.py
python3 login_investigator.py
```

The investigation script prints its findings and writes `investigation_report.txt` in the project folder.

## Run the tests

```bash
cd ~/cyberlab
python3 -m unittest discover -v
```

The current tests cover rolling-window thresholds, out-of-order events, successful-login handling, malformed records, and investigation risk scoring.

## Input and sample data

The project includes these sample files:

- `sample_auth.log`: username and status records for the first detector.
- `sample_auth_v2.log`: username, source IP, and status records.
- `sample_auth_v3.log`: timestamped records consumed by `login_detector_v2.py`.
- `sample_investigation.csv`: headed CSV input consumed by `login_investigator.py`.

The sample usernames are fictional. The sample IPs use reserved documentation ranges, so they do not identify real login sources. Use synthetic or appropriately sanitized data when experimenting; do not publish real authentication logs.

## Project files

| File | Purpose |
| --- | --- |
| `login_detector.py` | Counts failed logins by username. |
| `ip_detector.py` | Counts failed and successful logins by source IP. |
| `time_window_detector.py` | Demonstrates a rolling-window detector in a direct script. |
| `login_detector_v2.py` | Reusable timestamped rolling-window detector and command-line example. |
| `login_investigator.py` | Scores successful logins after recent failures and writes a report. |
| `test_login_detector.py` | Tests the reusable rolling-window detector. |
| `test_login_investigator.py` | Tests the investigation and risk-scoring function. |

## Limitations

- This is a simple offline rules exercise. It does not block logins, connect to an identity provider, or send alerts to a monitoring system.
- The source IP detector uses fixed thresholds and emits at most one alert per IP for a run.
- The investigator groups recent failures by source IP, not by both username and IP. Failures for one account can therefore affect the score of a later success for another account on the same IP.
- Timestamps are parsed without timezone information. The investigator interprets the hour as written in the input and does not convert between time zones.
- The timestamp detector expects a fixed comma-separated record format and timestamp layout; it is not a general-purpose authentication-log parser.
- There is no persistent state, alert deduplication across runs, or production hardening.

## Possible next steps

- Accept input path, threshold, time window, and working hours as command-line options.
- Add timezone-aware timestamps and configurable time zones.
- Correlate on both username and source IP, and add tests for shared-IP scenarios.
- Export structured JSON alerts and add an integration-ready logging interface.
- Add test coverage for missing CSV columns, invalid timestamps, and boundary conditions.
- Add continuous integration for the test suite.

## License

No license file is included. Add a license if you want to grant others permission to reuse or adapt this project.
