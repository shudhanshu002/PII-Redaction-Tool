# PII Redaction Engine for Word Documents

A Python-based tool for removing Personally Identifiable Information (PII) from financial and legal `.docx` files, such as Red Herring Prospectuses.

## Live Demo
[]

## GitHub URL
[]

## Approach & Methodology
The tool uses multiple techniques to detect and replace sensitive information with synthetic data while keeping the document structure intact:

1. **Gazetteer Dictionary Matching**: Matches known entities such as promoter names, trusts, and financial institutions using flexible patterns to handle formatting differences in Word documents.
2. **Regex Pattern Detection**: Uses regular expressions to detect structured information such as PAN numbers, Aadhaar numbers, phone numbers, email addresses, and URLs.
3. **SpaCy Named Entity Recognition (NER)**: Uses the `en_core_web_sm` model to identify person and organization names, while avoiding important domain-specific financial terms.
4. **Image Stream Clearing**: Replaces embedded image data inside the `.docx` package with a transparent placeholder to avoid exposing PII present in scanned documents.

## Local Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run CLI script
python pii_redactor.py "Red Herring Prospectus.docx" "Redacted_Output.docx"

# Run Streamlit Web UI
streamlit run app.py