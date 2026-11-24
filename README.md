# GP1 log analysis tool (Group 7): needs only Python 3.8+, no extra packages.
Put the 3 CSV files and `hashes.sha256` in a folder named `logs/`, then run: `python3 gp1_tool.py logs/`
Output: a merged UTC/EAT timeline, events flagged by the 3 detection rules, and SHA-256 MATCH/MISMATCH for each file.
Add `--full` to print every event. `--init` records the hash baseline once, at collection, and never overwrites it.
The tool only reads the CSV files; it exits with code 1 if any hash is a MISMATCH.
