#!/usr/bin/env python3
"""
this script is to generate a PDF report
"""
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(filename, title, main):
  """Generates a PDF report with a title and main content"""
  styles = getSampleStyleSheet()
  report = SimpleDocTemplate(filename)
  report_title = Paragraph(title, styles["h1"])
  report_info = Paragraph(main, styles["BodyText"])
  empty_line = Spacer(1,20)
  report.build([report_title, empty_line, report_info, empty_line])
