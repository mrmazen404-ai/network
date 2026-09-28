# core/exporter.py
import csv
import os
from datetime import datetime
from core.database import db

def export_alerts_to_csv(filepath):
    alerts = db.get_alerts(limit=1000)
    with open(filepath, mode="w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Timestamp", "Type", "Severity", "Source IP", "Destination IP", "Message"])
        for a in alerts:
            writer.writerow([a["id"], a["timestamp"], a["type"], a["severity"], a["src_ip"], a["dst_ip"], a["message"]])
    return filepath

def export_devices_to_csv(filepath):
    devices = db.get_devices()
    with open(filepath, mode="w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "IP Address", "MAC Address", "Vendor", "Hostname", "Device Type", "First Seen", "Last Seen"])
        for d in devices:
            writer.writerow([d["id"], d["ip"], d["mac"], d["vendor"], d.get("hostname", ""), d.get("device_type", ""), d["first_seen"], d["last_seen"]])
    return filepath

def export_packets_to_pcap(packet_list, filepath):
    """Enterprise Feature: Export captured raw packets to Wireshark-compatible PCAP format"""
    try:
        from scapy.utils import wrpcap
        wrpcap(filepath, packet_list)
        return filepath
    except Exception as e:
        raise RuntimeError(f"Failed to export PCAP file: {e}")

def export_alerts_to_pdf(filepath):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=12
        )
        elements.append(Paragraph("Network Security Monitor - Enterprise Security Report", title_style))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 12))

        alerts = db.get_alerts(limit=200)
        table_data = [["Time", "Type", "Severity", "Source", "Destination", "Message"]]
        for a in alerts:
            table_data.append([
                str(a["timestamp"])[11:19],
                str(a["type"]),
                str(a["severity"]),
                str(a["src_ip"]),
                str(a["dst_ip"]),
                str(a["message"])[:40]
            ])

        t = Table(table_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t)
        doc.build(elements)
        return filepath
    except Exception as e:
        txt_path = filepath.replace(".pdf", ".txt")
        alerts = db.get_alerts(limit=200)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("Network Security Monitor - Enterprise Incident Report\n")
            f.write("====================================================\n\n")
            for a in alerts:
                f.write(f"[{a['timestamp']}] {a['severity']} | {a['type']} | Src: {a['src_ip']} -> Dst: {a['dst_ip']} | {a['message']}\n")
        return txt_path
