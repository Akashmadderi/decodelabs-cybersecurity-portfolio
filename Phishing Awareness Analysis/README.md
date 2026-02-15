## Decodelabs Internship - Task 3: Phishing Awareness Analysis

### Overview
This task automates the analysis of sample emails and messages to identify phishing attempts. The program utilizes heuristic rule-based detection and regular expressions to scan text blocks for common Indicators of Compromise (IoCs).

### Key Requirements Met
* Identifies suspicious links and psychological trigger keywords within the text body.
* Lists specific red flags found in the provided phishing messages.
* Explains why the analyzed message is unsafe and outlines the potential security risks.

### Technical Skills Demonstrated
* Threat analysis and awareness of social engineering cyber attacks.
* Implementation of heuristic security thinking.
* Use of Python regular expressions (`re` module) for URL extraction and pattern matching.

### Execution Instructions
1. Open a terminal or IDE console.
2. Run the script using the command: `python task3_phishing_analyzer.py`
3. Paste the raw text of the suspicious email or message into the terminal.
4. Type `ANALYZE` on a new line and press Enter. The console will output a detailed threat report, listing all red flags and an explanation of the risk.