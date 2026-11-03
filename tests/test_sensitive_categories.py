import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sensitive_data_scanner as scanner


class SensitiveCategoryTests(unittest.TestCase):
    SAMPLES = {
        "government_identifiers": "SSN: 123-45-6789",
        "payment_cards": "Card 4111 1111 1111 1111",
        "payment_banking": "IBAN: GB82WEST12345698765432",
        "login_secrets": "Password: S3cretXYZ",
        "personal_identifiers": "Name: Jane Smith; jane@example.com",
        "identifying_documents": "Please attach the bank statement.",
        "health_status_information": "Diagnosis: chronic migraine",
        "staff_discipline": "Written warning: missed required safety checks",
        "hr_private_data": "Employee ID: 123456",
        "genetic_biometric": "DNA result: positive marker",
        "criminal_information": "Criminal conviction: theft",
        "employment_financial": "Credit report: overdue account",
    }

    def test_each_category_has_a_working_rule(self):
        for category, text in self.SAMPLES.items():
            with self.subTest(category=category):
                matches = scanner._rule_matches(
                    text, enabled_categories={category})
                self.assertTrue(matches)

    def test_disabled_category_is_not_detected_or_masked(self):
        args = SimpleNamespace(
            disabled_categories=["government_identifiers"],
            keep_emails=False,
            ner=False,
        )
        text = "SSN: 123-45-6789"
        findings = scanner.run_rules(
            text, 1, enabled_categories=scanner._enabled_category_ids(args))
        self.assertFalse(findings)
        self.assertEqual(scanner._sensitive_spans(text, args), [])
        self.assertIn("123-45-6789", scanner._sanitize_page_for_llm(text, args))

    def test_card_data_and_banking_categories_are_independent(self):
        card = "Card 4111 1111 1111 1111"
        banking = "IBAN: GB82WEST12345698765432"
        self.assertTrue(scanner._rule_matches(card, enabled_categories={"payment_cards"}))
        self.assertFalse(scanner._rule_matches(card, enabled_categories={"payment_banking"}))
        self.assertTrue(scanner._rule_matches(
            banking, enabled_categories={"payment_banking"}))
        self.assertFalse(scanner._rule_matches(
            banking, enabled_categories={"payment_cards"}))

    def test_removed_categories_are_not_available_or_detected(self):
        removed = {
            "sensitive_characteristics",
            "location_identifiers",
            "private_communications",
        }
        self.assertTrue(removed.isdisjoint(scanner.SENSITIVE_CATEGORY_IDS))
        for text in (
            "Religion: Sikh",
            "IP address 192.168.1.10",
            "Customer records are attached.",
        ):
            with self.subTest(text=text):
                matches = scanner._rule_matches(text)
                self.assertFalse(any(
                    category in {
                        "Sensitive characteristic (labelled)",
                        "IP address",
                        "Device or online identifier (labelled)",
                        "Private or third-party record reference",
                    }
                    for _, _, category, _, _ in matches
                ))

    def test_health_and_hr_controls_gate_detection_and_masking(self):
        examples = (
            ("health_status_information", "Diagnosis: chronic migraine"),
            ("staff_discipline", "Written warning: missed required safety checks"),
            ("hr_private_data", "Employee ID: 123456"),
        )
        for category, text in examples:
            with self.subTest(category=category):
                args = SimpleNamespace(
                    disabled_categories=[category],
                    keep_emails=False,
                    ner=False,
                )
                self.assertFalse(scanner.run_rules(
                    text, 1, enabled_categories=scanner._enabled_category_ids(args)))
                self.assertEqual(scanner._sensitive_spans(text, args), [])
                self.assertIn(text.split(": ", 1)[-1],
                              scanner._sanitize_page_for_llm(text, args))

    def test_legacy_health_category_id_disables_health_status(self):
        args = SimpleNamespace(
            disabled_categories=["health_information"],
            keep_emails=False,
            ner=False,
        )
        self.assertNotIn(
            "health_status_information", scanner._enabled_category_ids(args))

    def test_international_government_ids_are_masked(self):
        args = SimpleNamespace(disabled_categories=[], keep_emails=False, ner=False)
        for text in ("Aadhaar: 2345 6789 1234", "PAN card number: ABCDE1234F"):
            with self.subTest(text=text):
                matches = scanner.run_rules(
                    text, 1, enabled_categories=scanner._enabled_category_ids(args))
                self.assertTrue(matches)
                self.assertTrue(scanner._sensitive_spans(text, args))

    def test_unlabeled_title_case_pair_is_not_a_name_finding(self):
        text = "Loans Shares"
        self.assertFalse(any(
            match[2] == "Possible person name"
            for match in scanner._rule_matches(text)))
        self.assertTrue(scanner._possible_name_spans(text))
        args = SimpleNamespace(disabled_categories=[], keep_emails=False, ner=False)
        self.assertEqual(scanner._sanitize_page_for_llm(text, args), "XXXXXXXXXXXX")

    def test_page_summary_row_height_fits_short_viewports(self):
        self.assertEqual(scanner._page_summary_rowheight(100), 60)
        self.assertEqual(scanner._page_summary_rowheight(300), 144)
        self.assertEqual(scanner._page_summary_rowheight(30), 48)

    def test_xlsx_scans_text_first_row_and_data_after_long_blank_gap(self):
        from openpyxl import Workbook

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sparse.xlsx"
            workbook = Workbook()
            sheet = workbook.active
            sheet.append(["first@example.com"])
            sheet["A1003"] = "later@example.com"
            workbook.save(path)

            chunks = list(scanner.pages_xlsx(path))

        scanned_text = "\n".join(text for _, text, _, _ in chunks)
        self.assertIn("first@example.com", scanned_text)
        self.assertIn("later@example.com", scanned_text)
        self.assertTrue(any(
            finding[2] == "Email address"
            for finding in scanner._rule_matches(scanned_text)))

    def test_xlsx_scans_formula_text_and_warns_without_cached_value(self):
        from openpyxl import Workbook

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "formulas.xlsx"
            workbook = Workbook()
            sheet = workbook.active
            sheet["A1"] = "formula"
            sheet["A2"] = '="SSN: 123-45-6789"'
            workbook.save(path)

            chunks = list(scanner.pages_xlsx(path))

        scanned_text = "\n".join(text for _, text, _, _ in chunks)
        warnings = [
            warning for _, _, _, page_warnings in chunks
            for warning in page_warnings
        ]
        self.assertIn("SSN: 123-45-6789", scanned_text)
        self.assertTrue(any(
            finding[2] == "US SSN"
            for finding in scanner._rule_matches(scanned_text)))
        self.assertTrue(any("formula results are unavailable" in warning
                            for warning in warnings))

    def test_docx_scans_comments_and_textboxes(self):
        import zipfile
        from docx import Document

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.docx"
            modified = Path(folder) / "with_extra_content.docx"
            document = Document()
            document.add_paragraph("Ordinary body text.")
            document.save(source)

            with zipfile.ZipFile(source) as original:
                files = {name: original.read(name) for name in original.namelist()}
            document_xml = files["word/document.xml"].replace(
                b"</w:body>",
                b"<w:p><w:r><w:drawing><w:txbxContent><w:p><w:r><w:t>"
                b"Text box SSN: 123-45-6789</w:t></w:r></w:p></w:txbxContent>"
                b"</w:drawing></w:r></w:p></w:body>",
            )
            files["word/document.xml"] = document_xml
            files["word/comments.xml"] = (
                b'<w:comments xmlns:w="http://schemas.openxmlformats.org/'
                b'wordprocessingml/2006/main"><w:comment w:id="0">'
                b'<w:p><w:r><w:t>Comment SSN: 987-65-4321</w:t></w:r>'
                b'</w:p></w:comment></w:comments>'
            )
            with zipfile.ZipFile(modified, "w") as updated:
                for name, content in files.items():
                    updated.writestr(name, content)

            scanned_text = "\n".join(
                text for _, text, _, _ in scanner.pages_docx(modified))

        self.assertIn("Text box SSN: 123-45-6789", scanned_text)
        self.assertIn("Comment SSN: 987-65-4321", scanned_text)

    def test_pdf_ocr_runs_on_mixed_text_and_image_pages(self):
        class FakeTextPage:
            def get_text_range(self):
                return "Selectable page text."

        class FakeRenderedPage:
            def to_pil(self):
                return "rendered image"

        class FakePage:
            def get_textpage(self):
                return FakeTextPage()

            def get_objects(self, filter):
                return [object()]

            def render(self, scale):
                return FakeRenderedPage()

        class FakePdfDocument(list):
            def __init__(self, path):
                super().__init__([FakePage()])

        fake_pdfium = SimpleNamespace(
            PdfDocument=FakePdfDocument,
            PdfiumError=RuntimeError,
            raw=SimpleNamespace(FPDF_PAGEOBJ_IMAGE=3),
        )
        with (
            patch.dict(sys.modules, {"pypdfium2": fake_pdfium}),
            patch.object(
                scanner, "_ocr_image",
                return_value=("OCR sensitive phrase", None),
            ) as ocr,
        ):
            pages = list(scanner.pages_pdf(Path("mixed.pdf")))

        self.assertEqual(len(pages), 1)
        self.assertIn("Selectable page text.", pages[0][1])
        self.assertIn("OCR sensitive phrase", pages[0][1])
        self.assertFalse(pages[0][3])
        ocr.assert_called_once_with("rendered image")
        with (
            patch.dict(sys.modules, {"pypdfium2": fake_pdfium}),
            patch.object(
                scanner, "_ocr_image",
                return_value=("", "Tesseract OCR is not installed or not available."),
            ),
        ):
            failed_pages = list(scanner.pages_pdf(Path("mixed.pdf")))
        self.assertTrue(any("could not be OCR-scanned" in warning
                            for warning in failed_pages[0][3]))

    def test_scan_result_tracks_coverage_warnings_and_context_gate(self):
        args = SimpleNamespace(
            verbose=False,
            disabled_categories=[],
            keep_emails=False,
            ignore_emails=False,
            ner=False,
            llm_all=False,
            model="model",
            host="http://127.0.0.1:11434",
            llm_timeout=1,
        )
        callback_events = []
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.docx"
            path.write_text("test", encoding="utf-8")
            with (
                patch.object(
                    scanner, "pages_docx",
                    return_value=iter([(
                        1, "Ordinary content.", False,
                        ["Unverified content warning."],
                    )]),
                ),
                patch.object(scanner, "run_llm", return_value=([], "Summary.")),
                patch.object(scanner, "summarize_document", return_value={
                    "description": "Test document.", "main_points": [],
                }),
            ):
                result = scanner.scan_file(
                    path, args,
                    on_page=lambda *event: callback_events.append(event),
                )

        self.assertEqual(
            result["coverage_warnings"], ["Unverified content warning."])
        self.assertEqual(
            result["page_summaries"][0]["context_analysis"], "Signal-gated")
        self.assertEqual(callback_events[0][3], "Signal-gated")

    def test_xlsx_redacts_sensitive_text_in_first_text_row(self):
        from openpyxl import Workbook, load_workbook

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.xlsx"
            destination = Path(folder) / "redacted.xlsx"
            workbook = Workbook()
            workbook.active["A1"] = "first@example.com"
            workbook.save(source)

            count = scanner._redact_xlsx(
                source,
                destination,
                SimpleNamespace(
                    disabled_categories=[],
                    keep_emails=False,
                    ignore_emails=False,
                    ner=False,
                ),
            )
            redacted = load_workbook(destination, data_only=True)
            redacted_value = redacted.active["A1"].value
            redacted.close()

        self.assertEqual(count, 1)
        self.assertNotEqual(redacted_value, "first@example.com")

    def test_gui_has_no_tabs_and_detection_options_are_upper_right(self):
        import tkinter as tk

        original_mainloop = tk.Tk.mainloop
        layout = {}

        def inspect_layout(app, *args, **kwargs):
            layout["window_title"] = app.title()
            layout["has_notebook"] = hasattr(app, "tabs")
            layout["main_content_parent"] = str(app.main_content.master)
            layout["main_content"] = str(app.main_content)
            layout["has_status_bar"] = app.status_bar.winfo_manager() == "pack"
            layout["status_parent"] = str(app.status_bar.master)
            layout["status_pack_side"] = str(app.status_bar.pack_info()["side"])
            layout["status_label"] = app.status_var.get()
            layout["progress_stage"] = app.progress_label_var.get()
            layout["progress_mode"] = str(app.progress.cget("mode"))
            layout["table_columns"] = tuple(
                map(str, app.table.cget("columns")))
            layout["table_headings"] = tuple(
                str(app.table.heading(column, "text"))
                for column in app.table.cget("columns"))
            layout["analyze_all_default"] = app.analyze_all_var.get()
            layout["has_context_analysis_column"] = (
                "context_analysis" in app.table.cget("columns"))
            layout["has_network_card"] = hasattr(app, "airgap_card")
            layout["document_card_parent"] = str(app.document_card.master)
            layout["overview_card_parent"] = str(app.document_overview_card.master)
            layout["document_cards"] = str(app.document_cards)
            layout["document_card_column"] = app.document_card.grid_info()["column"]
            layout["document_card_column_weight"] = int(
                app.document_cards.grid_columnconfigure(0)["weight"])
            layout["detection_column_weight"] = int(
                app.document_cards.grid_columnconfigure(1)["weight"])
            layout["scan_button_side"] = str(app.scan_button.pack_info()["side"])
            layout["choose_button_side"] = str(app.choose_button.pack_info()["side"])
            layout["category_columns"] = {
                child.cget("text"): int(child.grid_info()["column"])
                for child in app.detection_options_frame.winfo_children()
                if child.winfo_class() == "TCheckbutton"
            }
            layout["detection_parent"] = str(app.detection_options_frame.master)
            layout["detection_frame"] = str(app.detection_options_frame)
            layout["detection_column"] = app.detection_options_frame.grid_info()["column"]
            layout["ner_parent"] = str(app.ner_checkbutton.master)
            layout["email_parent"] = str(app.detect_emails_checkbutton.master)
            layout["ner_text"] = app.ner_checkbutton.cget("text")
            layout["email_text"] = app.detect_emails_checkbutton.cget("text")
            layout["email_default"] = app.detect_emails_var.get()
            layout["ner_default"] = app.ner_var.get()
            layout["category_ids"] = set(app.category_vars)
            layout["category_labels"] = {
                child.cget("text")
                for child in app.detection_options_frame.winfo_children()
                if child.winfo_class() == "TCheckbutton"
            }
            app.destroy()

        tk.Tk.mainloop = inspect_layout
        try:
            scanner.launch_gui()
        finally:
            tk.Tk.mainloop = original_mainloop

        self.assertFalse(layout["has_notebook"])
        self.assertEqual(layout["window_title"], "Local Sensitive Data Scanner")
        self.assertIn("frame", layout["main_content_parent"])
        self.assertTrue(layout["has_status_bar"])
        self.assertEqual(layout["status_parent"], ".")
        self.assertEqual(layout["status_pack_side"], "bottom")
        self.assertEqual(layout["status_label"], "Ready - choose a document to scan.")
        self.assertEqual(layout["progress_stage"], "Ready")
        self.assertEqual(layout["progress_mode"], "indeterminate")
        self.assertNotIn("location", layout["table_columns"])
        self.assertNotIn("Location", layout["table_headings"])
        self.assertFalse(layout["analyze_all_default"])
        self.assertTrue(layout["has_context_analysis_column"])
        self.assertFalse(layout["has_network_card"])
        self.assertEqual(layout["document_card_parent"], layout["document_cards"])
        self.assertEqual(layout["detection_parent"], layout["document_cards"])
        self.assertEqual(layout["overview_card_parent"], layout["main_content"])
        self.assertEqual(layout["document_card_column"], 0)
        self.assertEqual(layout["detection_column"], 1)
        self.assertEqual(layout["document_card_column_weight"], 1)
        self.assertEqual(layout["detection_column_weight"], 2)
        self.assertEqual(layout["scan_button_side"], "left")
        self.assertEqual(layout["choose_button_side"], "left")
        self.assertEqual(
            {layout["category_columns"][label] for label in (
                "Government identifiers",
                "Card data",
                "Payment and banking",
                "Login and security secrets",
            )},
            {0, 1, 2, 3},
        )
        self.assertEqual(layout["ner_parent"], layout["detection_frame"])
        self.assertEqual(layout["email_parent"], layout["detection_frame"])
        self.assertEqual(layout["ner_text"], "Named Entity Recognition (NER)")
        self.assertEqual(layout["email_text"], "Email addresses")
        self.assertTrue(layout["email_default"])
        self.assertFalse(layout["ner_default"])
        self.assertIn("payment_cards", layout["category_ids"])
        self.assertIn("payment_banking", layout["category_ids"])
        self.assertIn("health_status_information", layout["category_ids"])
        self.assertIn("staff_discipline", layout["category_ids"])
        self.assertIn("hr_private_data", layout["category_ids"])
        self.assertTrue({
            "sensitive_characteristics",
            "location_identifiers",
            "private_communications",
        }.isdisjoint(layout["category_ids"]))
        self.assertIn("Card data", layout["category_labels"])
        self.assertIn("Payment and banking", layout["category_labels"])
        self.assertIn("Health status information", layout["category_labels"])
        self.assertIn("Staff discipline", layout["category_labels"])
        self.assertIn("HR private data", layout["category_labels"])

    def test_html_report_does_not_include_location_column(self):
        result = {
            "file": "sample.docx",
            "sha256": "abc123",
            "pages_scanned": 1,
            "findings": [],
            "page_summaries": [{
                "page": 1,
                "summary": "No sensitive content.",
                "context_analysis": "Signal-gated",
            }],
            "document_summary": None,
            "document_summary_error": None,
            "clean_pages": [1],
            "coverage_warnings": ["Formula results could not be verified."],
            "error": None,
            "seconds": 0,
        }
        args = SimpleNamespace(model="qwen3:4b", ner=False)

        with tempfile.TemporaryDirectory() as temp_dir:
            scanner.write_reports([result], Path(temp_dir), args)
            report_path = next(Path(temp_dir).glob("scan_*.html"))
            report = report_path.read_text(encoding="utf-8")

        self.assertIn("<th>Page</th>", report)
        self.assertNotIn("Page / location", report)
        self.assertNotIn("<th>Location</th>", report)
        self.assertIn("Formula results could not be verified.", report)
        self.assertIn("Signal-gated", report)

    def test_email_preservation_still_detects_but_does_not_mask_email(self):
        args = SimpleNamespace(
            disabled_categories=[],
            keep_emails=True,
            ner=False,
        )
        text = "Contact jane@example.com"
        findings = scanner.run_rules(
            text, 1, keep_emails=True,
            enabled_categories=scanner._enabled_category_ids(args))
        self.assertTrue(any(f.category == "Email address" for f in findings))
        self.assertEqual(scanner._sensitive_spans(text, args), [])

    def test_ignore_emails_excludes_findings_and_redaction_spans(self):
        args = SimpleNamespace(
            disabled_categories=[],
            keep_emails=False,
            ignore_emails=True,
            ner=False,
        )
        text = "Contact jane@example.com"
        findings = scanner.run_rules(
            text,
            1,
            enabled_categories=scanner._enabled_category_ids(args),
            ignore_emails=True,
        )
        self.assertFalse(any(f.category == "Email address" for f in findings))
        self.assertEqual(scanner._sensitive_spans(text, args), [])
        self.assertIn("jane@example.com", scanner._sanitize_page_for_llm(text, args))

    def test_ner_results_follow_their_category_toggle(self):
        with patch.object(
            scanner, "_ner_matches", return_value=[(0, 5, "PERSON", 0.9)]
        ):
            self.assertFalse(scanner.run_ner(
                "Alice", 1, enabled_categories={"government_identifiers"}))
            self.assertEqual(len(scanner.run_ner(
                "Alice", 1, enabled_categories={"personal_identifiers"})), 1)

    def test_llm_findings_respect_enabled_categories(self):
        raw = [{
            "category": "Health or medical information about a person",
            "evidence": "on medical leave",
            "confidence": "high",
        }]
        finding_text = "on medical leave"
        self.assertFalse(scanner._verify_llm_findings(
            raw, finding_text, 1,
            {"HR or employment action about a person"}))
        self.assertTrue(scanner._verify_llm_findings(
            raw, finding_text, 1,
            {"Health or medical information about a person"}))

    def test_llm_evidence_accepts_short_exact_masked_phrases(self):
        raw = [{
            "category": "Pay or compensation of a specific person",
            "evidence": "pay XXXXXXXX",
            "confidence": "medium",
        }]

        findings = scanner._verify_llm_findings(
            raw,
            "The employee pay XXXXXXXX was adjusted.",
            1,
            {"Pay or compensation of a specific person"},
        )

        self.assertEqual(len(findings), 1)

    def test_llm_evidence_still_rejects_generic_or_unmatched_phrases(self):
        category = "Pay or compensation of a specific person"
        generic = [{
            "category": category,
            "evidence": "the XXXXXXXX",
            "confidence": "medium",
        }]
        unmatched = [{
            "category": category,
            "evidence": "bonus XXXXXXXX",
            "confidence": "medium",
        }]

        self.assertFalse(scanner._verify_llm_findings(
            generic, "the XXXXXXXX", 1, {category}))
        self.assertFalse(scanner._verify_llm_findings(
            unmatched, "pay XXXXXXXX", 1, {category}))

    def test_new_health_and_hr_toggles_control_llm_categories(self):
        enabled = scanner._enabled_llm_categories({
            "health_status_information",
            "staff_discipline",
        })
        self.assertIn("Health or medical information about a person", enabled)
        self.assertIn("Staff disciplinary information about an employee", enabled)
        self.assertNotIn("Private HR information about an employee", enabled)

    def test_run_llm_builds_schema_for_enabled_categories(self):
        requests = []

        class FakeOpener:
            def open(self, request, timeout):
                requests.append(json.loads(request.data))
                response = {
                    "response": json.dumps({
                        "summary_points": ["Review the case."],
                        "findings": [{
                            "category": "Health or medical information about a person",
                            "evidence": "medical history",
                            "confidence": "high",
                        }],
                    }),
                }
                return io.BytesIO(json.dumps(response).encode("utf-8"))

        args = SimpleNamespace(
            disabled_categories=["health_information"],
            keep_emails=False,
            ner=False,
        )
        with patch.object(scanner, "_ollama_opener", return_value=FakeOpener()):
            findings, _ = scanner.run_llm(
                "A patient has a medical history.", 1, "model", "http://127.0.0.1:11434",
                1, args, want_findings=True)

        allowed = requests[0]["format"]["properties"]["findings"]["items"]
        self.assertNotIn(
            "Health or medical information about a person",
            allowed["properties"]["category"]["enum"])
        self.assertFalse(findings)

    def test_run_llm_analyzes_text_beyond_first_chunk(self):
        requests = []
        marker = "confidential details"

        class FakeOpener:
            def open(self, request, timeout):
                payload = json.loads(request.data)
                requests.append(payload)
                findings = [{
                    "category": "Other personal data about a specific person",
                    "evidence": marker,
                    "confidence": "medium",
                }] if marker in payload["prompt"] else []
                response = {
                    "response": json.dumps({
                        "summary_points": ["Page content reviewed."],
                        "findings": findings,
                    }),
                }
                return io.BytesIO(json.dumps(response).encode("utf-8"))

        args = SimpleNamespace(
            disabled_categories=[],
            keep_emails=False,
            ignore_emails=False,
            ner=False,
        )
        text = (
            "Routine administrative notes continue. " * 200
            + "Additional confidential details are recorded here."
        )

        with patch.object(scanner, "_ollama_opener", return_value=FakeOpener()):
            findings, summary = scanner.run_llm(
                text, 1, "model", "http://127.0.0.1:11434",
                1, args, want_findings=True)

        self.assertGreater(len(requests), 1)
        self.assertTrue(any(marker in payload["prompt"] for payload in requests))
        self.assertTrue(any(
            finding.category == "Other personal data about a specific person"
            for finding in findings))
        self.assertTrue(summary)

    def test_pdf_redaction_accepts_multiple_rectangles_for_one_match(self):
        class FakePage:
            def __init__(self):
                self.annotations = []

            def search_for(self, value):
                self.asserted_value = value
                return ["first line rect", "second line rect"]

            def add_redact_annot(self, rect, **kwargs):
                self.annotations.append((rect, kwargs))

            def apply_redactions(self, **kwargs):
                pass

        class FakeDocument:
            def __init__(self, page):
                self.page = page
                self.saved = False

            def __iter__(self):
                return iter([self.page])

            def save(self, *args, **kwargs):
                self.saved = True

            def close(self):
                pass

        page = FakePage()
        document = FakeDocument(page)
        fake_pymupdf = SimpleNamespace(open=lambda path: document)
        args = SimpleNamespace(disabled_categories=[], keep_emails=False, ner=False)

        with (
            patch.dict(sys.modules, {"pymupdf": fake_pymupdf}),
            patch.object(
                scanner, "pages_pdf",
                return_value=iter([(1, "SSN: 123-45-6789", False, [])]),
            ),
        ):
            count = scanner._redact_pdf(
                Path("sample.pdf"), Path("redacted.pdf"), args)

        self.assertEqual(count, 1)
        self.assertEqual(len(page.annotations), 2)
        self.assertTrue(document.saved)

    def test_pdf_redaction_fails_closed_when_match_has_no_rectangle(self):
        class FakePage:
            def search_for(self, value):
                return []

            def get_text(self, mode):
                return []

        class FakeDocument:
            def __init__(self):
                self.saved = False

            def __iter__(self):
                return iter([FakePage()])

            def save(self, *args, **kwargs):
                self.saved = True

            def close(self):
                pass

        document = FakeDocument()
        args = SimpleNamespace(disabled_categories=[], keep_emails=False, ner=False)
        with (
            patch.dict(sys.modules, {
                "pymupdf": SimpleNamespace(open=lambda path: document),
            }),
            patch.object(
                scanner, "pages_pdf",
                return_value=iter([(1, "SSN: 123-45-6789", False, [])]),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "No redacted copy was saved"):
                scanner._redact_pdf(
                    Path("sample.pdf"), Path("redacted.pdf"), args)

        self.assertFalse(document.saved)

    def test_pdf_word_fallback_maps_exact_token_sequence(self):
        class FakePage:
            def search_for(self, value):
                return []

            def get_text(self, mode):
                return [
                    (10, 10, 30, 20, "Jane", 0, 0, 0),
                    (32, 10, 52, 20, "Smith", 0, 0, 1),
                    (10, 30, 40, 40, "Jane", 0, 1, 0),
                    (42, 30, 62, 40, "Smith", 0, 1, 1),
                ]

        rects = scanner._pdf_match_rects(FakePage(), "Jane\nSmith")
        self.assertEqual(len(rects), 4)

    def test_docx_redaction_spans_formatted_runs(self):
        from docx import Document

        paragraph = Document().add_paragraph()
        paragraph.add_run("SSN: 123-")
        paragraph.add_run("45-6789").bold = True

        count = scanner._redact_paragraph(paragraph, [(5, 16)])

        self.assertEqual(count, 1)
        self.assertEqual(paragraph.text, "SSN: XXXXXXXXXXX")

    def test_docx_redaction_supports_hyperlink_text(self):
        from docx import Document
        from docx.oxml import OxmlElement

        paragraph = Document().add_paragraph("Contact ")
        hyperlink = OxmlElement("w:hyperlink")
        hyperlink.set(
            "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}anchor",
            "contact",
        )
        run = OxmlElement("w:r")
        text = OxmlElement("w:t")
        text.text = "Jane Smith"
        run.append(text)
        hyperlink.append(run)
        paragraph._p.append(hyperlink)

        count = scanner._redact_paragraph(paragraph, [(8, 18)])

        self.assertEqual(count, 1)
        self.assertEqual(text.text, "XXXXXXXXXX")

    def test_docx_redacted_copy_preserves_formatted_paragraphs(self):
        from docx import Document

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.docx"
            destination = Path(folder) / "redacted.docx"
            document = Document()
            paragraph = document.add_paragraph()
            paragraph.add_run("SSN: 123-")
            paragraph.add_run("45-6789").bold = True
            document.save(source)

            count = scanner._redact_docx(
                source,
                destination,
                SimpleNamespace(
                    disabled_categories=[],
                    keep_emails=False,
                    ner=False,
                ),
            )

            redacted_document = Document(destination)
            self.assertEqual(count, 1)
            self.assertEqual(redacted_document.paragraphs[0].text, "SSN: XXXXXXXXXXX")


if __name__ == "__main__":
    unittest.main()
