import re
from dataclasses import dataclass
from pathlib import Path

import docx
import spacy
from faker import Faker


@dataclass
class PIIMatch:
    """Represents one piece of detected PII."""

    pii_type: str
    value: str
    start: int
    end: int


class PIIRedactor:
    def __init__(self):
        self.fake = Faker("en_IN")
        self.nlp = spacy.load("en_core_web_sm")

        # Keeps replacements stable throughout the document.
        # Example:
        # "Rashi Patil" -> "John Doe"
        # Every later occurrence of Rashi Patil gets the same replacement.
        self.replacements = {}

        self.patterns = {
            "EMAIL": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),

            "PHONE": re.compile(
                r"(?<!\d)"
                r"(?:\+91[\s-]?)?"
                r"(?:[6-9]\d{4}[\s-]?\d{5})"
                r"(?!\d)"
            ),

            "IP_ADDRESS": re.compile(
                r"\b(?:"
                r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
                r"){3}"
                r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                r"\b"
            ),

            "SSN": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),

            "CREDIT_CARD": re.compile(
                r"(?<!\d)"
                r"(?:\d[ -]?){13,19}"
                r"(?!\d)"
            ),

            "DOB": re.compile(
                r"\b(?:"
                r"(?:0?[1-9]|[12]\d|3[01])[-/.]"
                r"(?:0?[1-9]|1[0-2])[-/.]"
                r"(?:19|20)\d{2}"
                r"|"
                r"(?:19|20)\d{2}[-/.]"
                r"(?:0?[1-9]|1[0-2])[-/.]"
                r"(?:0?[1-9]|[12]\d|3[01])"
                r")\b"
            ),
        }

    # ------------------------------------------------------------------
    # Fake value generation
    # ------------------------------------------------------------------

    def _generate_replacement(self, pii_type: str) -> str:
        """Generate a fake value appropriate for the PII category."""

        if pii_type == "EMAIL":
            return self.fake.unique.email()

        if pii_type == "PHONE":
            return f"+91 {self.fake.msisdn()[-10:]}"

        if pii_type == "PERSON":
            return self.fake.unique.name()

        if pii_type == "COMPANY":
            return self.fake.unique.company()

        if pii_type == "ADDRESS":
            address = self.fake.address()
            return " ".join(address.split())

        if pii_type == "SSN":
            return self.fake.ssn()

        if pii_type == "CREDIT_CARD":
            return self.fake.credit_card_number()

        if pii_type == "DOB":
            return self.fake.date_of_birth().strftime("%d/%m/%Y")

        if pii_type == "IP_ADDRESS":
            return self.fake.ipv4_private()

        return "[REDACTED]"

    def replacement_for(self, pii_type: str, original: str) -> str:
        """
        Return a consistent fake value for a detected PII value.

        The same original value will always receive the same replacement.
        """

        key = (pii_type, original)

        if key not in self.replacements:
            self.replacements[key] = self._generate_replacement(pii_type)

        return self.replacements[key]

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def valid_credit_card(number: str) -> bool:
        """
        Validate a credit-card candidate using the Luhn algorithm.
        """

        digits = re.sub(r"\D", "", number)

        if not 13 <= len(digits) <= 19:
            return False

        total = 0
        reverse_digits = digits[::-1]

        for index, digit in enumerate(reverse_digits):
            value = int(digit)

            if index % 2 == 1:
                value *= 2

                if value > 9:
                    value -= 9

            total += value

        return total % 10 == 0

    # ------------------------------------------------------------------
    # Regex-based detection
    # ------------------------------------------------------------------

    def detect_regex_pii(self, text: str) -> list[PIIMatch]:
        """Find deterministic PII using regular expressions."""

        matches = []

        for pii_type, pattern in self.patterns.items():

            for match in pattern.finditer(text):
                value = match.group(0)

                # Credit-card regex can match ordinary long numbers.
                # Only keep candidates passing Luhn validation.
                if pii_type == "CREDIT_CARD":
                    if not self.valid_credit_card(value):
                        continue

                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                    )
                )

        return matches

    # ------------------------------------------------------------------
    # NER-based detection
    # ------------------------------------------------------------------

    def detect_ner_pii(self, text: str) -> list[PIIMatch]:
        """
        Detect names and organizations using spaCy NER.

        Locations are intentionally not automatically classified as
        physical addresses because a city name alone is not an address.
        """

        document = self.nlp(text)
        matches = []

        for entity in document.ents:

            if entity.label_ == "PERSON":
                matches.append(
                    PIIMatch(
                        pii_type="PERSON",
                        value=entity.text,
                        start=entity.start_char,
                        end=entity.end_char,
                    )
                )

            elif entity.label_ == "ORG":
                matches.append(
                    PIIMatch(
                        pii_type="COMPANY",
                        value=entity.text,
                        start=entity.start_char,
                        end=entity.end_char,
                    )
                )

        return matches

    # ------------------------------------------------------------------
    # Combined detection
    # ------------------------------------------------------------------

    def detect_pii(self, text: str) -> list[PIIMatch]:
        """Run all available detectors and remove overlapping matches."""

        detected = []

        detected.extend(self.detect_regex_pii(text))
        detected.extend(self.detect_ner_pii(text))

        # Sort by location in the original text.
        detected.sort(key=lambda item: (item.start, -(item.end - item.start)))

        # Avoid overlapping detections.
        final_matches = []

        for current in detected:

            overlaps_existing = False

            for previous in final_matches:
                if (
                    current.start < previous.end
                    and current.end > previous.start
                ):
                    overlaps_existing = True
                    break

            if not overlaps_existing:
                final_matches.append(current)

        return final_matches

    # ------------------------------------------------------------------
    # Text replacement
    # ------------------------------------------------------------------

    def redact_text(self, text: str) -> str:
        """Detect PII in a text block and replace it from right to left."""

        if not text or not text.strip():
            return text

        matches = self.detect_pii(text)

        # Replace from the end of the string toward the beginning.
        # This prevents earlier indexes from becoming invalid.
        for match in reversed(matches):

            replacement = self.replacement_for(
                match.pii_type,
                match.value,
            )

            text = (
                text[:match.start]
                + replacement
                + text[match.end:]
            )

        return text

    # ------------------------------------------------------------------
    # DOCX processing
    # ------------------------------------------------------------------

    def process_paragraph(self, paragraph):
        """Redact text inside a paragraph."""

        if paragraph.text.strip():
            paragraph.text = self.redact_text(paragraph.text)

    def process_table(self, table):
        """Redact all text contained in a table."""

        for row in table.rows:
            for cell in row.cells:

                for paragraph in cell.paragraphs:
                    self.process_paragraph(paragraph)

                for nested_table in cell.tables:
                    self.process_table(nested_table)

    def redact_document(self, input_path: str, output_path: str):
        """
        Read a DOCX file, redact PII from paragraphs and tables,
        and save the resulting document.
        """

        input_file = Path(input_path)
        output_file = Path(output_path)

        if not input_file.exists():
            raise FileNotFoundError(
                f"Input document was not found: {input_file}"
            )

        document = docx.Document(input_file)

        # Main document paragraphs
        for paragraph in document.paragraphs:
            self.process_paragraph(paragraph)

        # Tables
        for table in document.tables:
            self.process_table(table)

        # Headers and footers
        for section in document.sections:

            for paragraph in section.header.paragraphs:
                self.process_paragraph(paragraph)

            for table in section.header.tables:
                self.process_table(table)

            for paragraph in section.footer.paragraphs:
                self.process_paragraph(paragraph)

            for table in section.footer.tables:
                self.process_table(table)

        output_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        document.save(output_file)

        print(f"Redacted document saved to: {output_file}")

        print("\nReplacement summary:")
        for (pii_type, original), replacement in self.replacements.items():
            print(
                f"{pii_type:15} "
                f"{original!r} -> {replacement!r}"
            )


def main():
    input_file = "input/input_ticket_log.docx"
    output_file = "output/redacted_output.docx"

    redactor = PIIRedactor()
    redactor.redact_document(
        input_file,
        output_file,
    )


if __name__ == "__main__":
    main()