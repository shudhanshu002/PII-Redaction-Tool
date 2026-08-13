import re
import docx
from faker import Faker
import spacy

nlp = spacy.load("en_core_web_sm")
fake = Faker("en_IN")

class PIIRedactor:
    def __init__(self):
        self.mapping = {}

        # 1. Stricter Regex Patterns including PAN and Aadhaar
        self.patterns = {
            "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            # Strict 10-digit Indian mobile format with optional +91 prefix. Avoids CIN matches.
            "PHONE": r'(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)', 
            "AADHAAR": r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
            "PAN_CARD": r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
            "IP_ADDRESS": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b',
            "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
            "DOB": r'\b(0[1-9]|1[0-2])[\/.-](0[1-9]|[12]\d|3[01])[\/.-](19|20)\d{2}\b|\b\d{4}[-/.](0[1-9]|1[02])[-/.](0[1-9]|[12]\d|3[01])\b',
        }

        # Words to explicitly ignore so SpaCy doesn't over-redact them
        self.ignore_words = {"SEBI", "Offer", "Equity", "Prospectus", "Book Building Process"}

    def get_fake_value(self, pii_type: str, original_text: str) -> str:
        # Normalize text to lowercase to ensure consistent mapping across the whole document
        normalized_text = original_text.strip().lower()

        if normalized_text in self.mapping:
            return self.mapping[normalized_text]

        if pii_type == "EMAIL":
            replacement = fake.unique.email()
        elif pii_type == "PHONE":
            # Replaces the entire match (including old prefix) with a clean fake number
            replacement = f"+91 {fake.msisdn()[3:13]}"
        elif pii_type == "AADHAAR":
            replacement = f"{fake.random_int(min=2000, max=9999)} {fake.random_int(min=1000, max=9999)} {fake.random_int(min=1000, max=9999)}"
        elif pii_type == "PAN_CARD":
            replacement = f"{fake.lexify(text='?????').upper()}{fake.numerify(text='####')}{fake.lexify(text='?').upper()}"
        elif pii_type == "PERSON":
            replacement = fake.unique.name()
        elif pii_type == "COMPANY":
            replacement = fake.unique.company()
        elif pii_type == "ADDRESS":
            replacement = fake.street_address().replace('\n', ', ')
        elif pii_type == "SSN":
            replacement = fake.ssn()
        elif pii_type == "CREDIT_CARD":
            replacement = fake.credit_card_number()
        elif pii_type == "DOB":
            replacement = fake.date_of_birth().strftime('%Y-%m-%d')
        elif pii_type == "IP_ADDRESS":
            replacement = fake.ipv4()
        else:
            replacement = "[REDACTED]"

        self.mapping[normalized_text] = replacement
        return replacement

    def detect_and_replace_text(self, text: str) -> str:
        if not text.strip():
            return text

        # Step A: Apply Regex replacements
        for pii_type, regex in self.patterns.items():
            matches = set(re.findall(regex, text))
            for match in matches:
                match_str = match if isinstance(match, str) else "".join(match)
                if match_str.strip():
                    fake_val = self.get_fake_value(pii_type, match_str)
                    text = text.replace(match_str, fake_val)

        # Step B: Apply SpaCy NER
        doc = nlp(text)
        entities = sorted(doc.ents, key=lambda e: e.start_char, reverse=True)

        for ent in entities:
            # Skip false positives and regulatory jargon
            if any(ignore_word.lower() in ent.text.lower() for ignore_word in self.ignore_words):
                continue

            if ent.label_ == "PERSON":
                fake_val = self.get_fake_value("PERSON", ent.text)
                text = text[:ent.start_char] + fake_val + text[ent.end_char:]
            elif ent.label_ in ["ORG"]:  
                fake_val = self.get_fake_value("COMPANY", ent.text)
                text = text[:ent.start_char] + fake_val + text[ent.end_char:]
            elif ent.label_ in ["FAC", "GPE", "LOC"]: 
                fake_val = self.get_fake_value("ADDRESS", ent.text)
                text = text[:ent.start_char] + fake_val + text[ent.end_char:]

        return text

    def redact_docx(self, input_docx_path: str, output_docx_path: str):
        doc = docx.Document(input_docx_path)

        for paragraph in doc.paragraphs:
            if paragraph.text:
                paragraph.text = self.detect_and_replace_text(paragraph.text)

        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for paragraph in cell.paragraphs:
                        if paragraph.text:
                            paragraph.text = self.detect_and_replace_text(paragraph.text)

        doc.save(output_docx_path)
        print(f"Redaction complete. Saved to: {output_docx_path}")

if __name__ == "__main__":
    redactor = PIIRedactor()
    redactor.redact_docx("Red_Herring_Prospectus.docx", "Redacted_Output.docx")