"""Update all fields (TOC, list of figures, list of tables) in Word and export PDFs.

    python docs/build/export_pdf.py

Requires Microsoft Word / PowerPoint on Windows (pywin32). The .docx is saved
back with populated tables of contents; PDFs are written next to it.
"""
from __future__ import annotations

import os
import sys

import win32com.client as win32

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(ROOT, "docs")


def export_report(name: str = "Project_Report") -> None:
    docx = os.path.join(DOCS, f"{name}.docx")
    pdf = os.path.join(DOCS, f"{name}.pdf")
    word = win32.DispatchEx("Word.Application")
    word.Visible = False
    word.DisplayAlerts = 0
    try:
        doc = word.Documents.Open(docx, ReadOnly=False, AddToRecentFiles=False)
        for _ in range(2):                       # second pass settles page numbers
            doc.Fields.Update()
            for toc in doc.TablesOfContents:
                toc.Update()
        doc.Save()
        doc.ExportAsFixedFormat(pdf, 17, OpenAfterExport=False, OptimizeFor=0,
                                CreateBookmarks=1, DocStructureTags=True)
        pages = doc.ComputeStatistics(2)          # wdStatisticPages
        doc.Close(False)
        print(f"report: {pages} pages -> {pdf}")
    finally:
        word.Quit()


def export_slides(name: str = "Presentation") -> None:
    pptx = os.path.join(DOCS, f"{name}.pptx")
    if not os.path.exists(pptx):
        return
    pdf = os.path.join(DOCS, f"{name}.pdf")
    ppt = win32.DispatchEx("PowerPoint.Application")
    try:
        pres = ppt.Presentations.Open(pptx, ReadOnly=True, Untitled=False, WithWindow=False)
        pres.SaveAs(pdf, 32)                      # ppSaveAsPDF
        n = pres.Slides.Count
        pres.Close()
        print(f"slides: {n} slides -> {pdf}")
    finally:
        ppt.Quit()


if __name__ == "__main__":
    what = sys.argv[1:] or ["report", "slides"]
    if "report" in what:
        export_report()
    if "slides" in what:
        export_slides()
