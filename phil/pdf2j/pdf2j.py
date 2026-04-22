import argparse
import json
import sys
from pathlib import Path

import pdfplumber


def extract_pdf(pdf_path: str) -> dict:
    path = Path(pdf_path)
    if not path.exists():
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)

    result = {
        "file": path.name,
        "pages": []
    }

    with pdfplumber.open(path) as pdf:
        result["total_pages"] = len(pdf.pages)
        result["metadata"] = pdf.metadata or {}

        for i, page in enumerate(pdf.pages, start=1):
            page_data = {
                "page": i,
                "text": page.extract_text() or "",
                "tables": page.extract_tables() or []
            }
            result["pages"].append(page_data)

    return result


def main():
    parser = argparse.ArgumentParser(description="Extract PDF content to JSON")
    parser.add_argument("pdf_path", help="Path to the PDF file")
    parser.add_argument("-o", "--output", help="Output JSON file path (default: <pdf_name>.json)")
    args = parser.parse_args()

    data = extract_pdf(args.pdf_path)

    output_path = args.output or Path(args.pdf_path).with_suffix(".json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    print(f"JSON saved to: {output_path}")


if __name__ == "__main__":
    main()