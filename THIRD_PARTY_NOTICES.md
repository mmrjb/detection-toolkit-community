# Third-party notices

Detection Toolkit v0.1 bundles only the files listed under "Bundled data". Python
packages are installed separately with `pip` from `requirements.txt` and are not
copied into this project.

## Bundled data

### MITRE ATT&CK®

`detection_toolkit/seed/attack-catalog-subset.json` is a subset of MITRE ATT&CK
Enterprise 19.2 (ten technique families: IDs, names, tactics, platforms and parent
links). Source: `enterprise-attack-19.2.json` from the mitre-attack/attack-stix-data
repository (SHA-256 recorded in the file).

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation.

The full license and disclaimer are in `licenses/MITRE-ATTACK-LICENSE.txt`.
ATT&CK® is a registered trademark of The MITRE Corporation.

### Demo content written for this edition

These files are original synthetic examples written for Detection Toolkit v0.1.
They are dedicated to the public domain under CC0-1.0
(https://creativecommons.org/publicdomain/zero/1.0/), except where noted:

- `detection_toolkit/seed/rules/*.yml`: seven small Sigma rules.
- `detection_toolkit/seed/demo_events.json` and `examples/sysmon-eid1-demo-events.jsonl`:
  two synthetic Sysmon Event ID 1 records.
- `detection_toolkit/seed/threat_reports.json`: two fictional threat rankings.
  They are not taken from any vendor report.
- `detection_toolkit/seed/telemetry.json`: the demo inventory, event types and field
  mappings. **Not** the `technique_requirements` section: that is curated guidance
  reused from the earlier Detection Toolkit and has the same licensing status as the
  project code (see below).
- `detection_toolkit/seed/plans.json`: one sample plan.

## Code reused from the earlier Detection Toolkit

Parts of the backend are copied or adapted from the owner's earlier Detection
Toolkit source, as noted in each module's docstring: the SQLite connection helper,
technique parsing, rule search filters, the pySigma conversion path, the data
source feasibility engine, the gap ranking model, the CSRF and security headers,
and the local Sigma sample evaluator.

This preview provides no license grant for the project code or the
`technique_requirements` guidance.

## Python dependencies (installed with pip, not bundled)

| Package | Version | License |
| --- | --- | --- |
| Flask (pulls in Werkzeug, Jinja2, itsdangerous, click, MarkupSafe, blinker) | 3.1.3 | BSD-3-Clause; blinker is MIT |
| PyYAML | 6.0.3 or newer 6.x | MIT |
| pySigma | 1.4.0 | LGPL-2.1-only |
| pysigma-backend-splunk | 2.1.0 | LGPL-2.1-only |

pySigma pulls in further packages (for example jq, pyparsing, requests, diskcache
and packaging) under their own licenses. pySigma and the Splunk backend are used
as unmodified libraries through their public API.

## Not included

This edition has no web fonts, no CSS framework build, no ATT&CK Navigator copy
and no logos. Its stylesheet and script are original.
