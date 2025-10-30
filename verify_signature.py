# ===========================================
# verify_signature.py
# Kiểm tra chữ ký PDF (chuẩn pyHanko 0.31+)
# ===========================================

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import format_pretty_print_details
from pyhanko_certvalidator import ValidationContext
from datetime import datetime
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
import argparse
import json
import os

# === ĐƯỜNG DẪN ===
PDF_PATH = r"E:\Bai2_Baomat\signed.pdf"
CERT_PATH = r"E:\Bai2_Baomat\keys\signer_cert.pem"

def parse_args():
    p = argparse.ArgumentParser(description="Xác minh chữ ký PDF (pyHanko)")
    p.add_argument("--pdf", default=PDF_PATH, help="Đường dẫn file PDF")
    p.add_argument("--cert", default=CERT_PATH, help="Đường dẫn chứng chỉ tin cậy (PEM)")
    p.add_argument("--json", action="store_true", help="Xuất kết quả ở dạng JSON")
    p.add_argument("--fetch-revocation", action="store_true", help="Cho phép fetch OCSP/CRL để kiểm tra revocation")
    return p.parse_args()


def main():
    args = parse_args()
    print("=== KIỂM TRA CHỮ KÝ TRONG FILE PDF ===")
    print(f"File: {args.pdf}")
    pdf_path = args.pdf
    cert_path = args.cert
    output_json = args.json
    allow_fetch = args.fetch_revocation

    # --- Kiểm tra tồn tại file ---
    if not os.path.exists(pdf_path):
        print(f"❌ Không tìm thấy file: {pdf_path}")
        exit(1)
    # === 1. Đọc PDF ===
    # Keep the file handle open while validating the embedded signature,
    # because EmbeddedPdfSignature instances may access the underlying
    # stream lazily.
    with open(pdf_path, "rb") as f:
        pdf_reader = PdfFileReader(f)
        sig_fields = list(pdf_reader.embedded_signatures)

        if not sig_fields:
            print("❌ Không tìm thấy chữ ký nào trong file PDF.")
            exit(1)

        print(f"✅ Phát hiện {len(sig_fields)} chữ ký trong PDF.")

        # === 2. Lấy chữ ký đầu tiên ===
        sig = sig_fields[0]
        sig_name = getattr(sig, "field_name", "UnknownField")

        print(f"🔍 Đang xác minh chữ ký: {sig_name}")

        # === 3. Tạo Validation Context (chứng chỉ tự ký) ===
        with open(cert_path, "rb") as cf:
            cert_data = cf.read()

        # Chuyển PEM/DER thành đối tượng certificate dùng asn1crypto
        try:
            if asn1_pem.detect(cert_data):
                _, _, der_bytes = asn1_pem.unarmor(cert_data)
            else:
                der_bytes = cert_data
            cert_obj = asn1_x509.Certificate.load(der_bytes)

            # Tạo ValidationContext với certificate object
            # allow_fetching enables OCSP/CRL retrieval if requested
            vc = ValidationContext(trust_roots=[cert_obj], allow_fetching=allow_fetch)
        except Exception as e:
            print(f"❌ Lỗi khi đọc chứng chỉ: {e}")
            exit(1)

        # === 4. Xác minh chữ ký ===
        # Note: pyHanko's validate_pdf_signature expects 'signer_validation_context'
        # as the parameter name (not 'validation_context'). Use that to avoid
        # unexpected keyword argument errors against different pyHanko versions.
        status = validate_pdf_signature(sig, signer_validation_context=vc)
        
        # Debug: kiểm tra kiểu dữ liệu của status và các thuộc tính
        print("\nDEBUG:")
        print(f"Type of status: {type(status)}")
        print(f"Has signed_data: {hasattr(status, 'signed_data')}")
        if hasattr(status, 'signed_data'):
            print(f"Type of signed_data: {type(status.signed_data)}")
            print(f"Has signer_infos: {hasattr(status.signed_data, 'signer_infos')}")
        print(f"Has signer_cert: {hasattr(status, 'signer_cert')}")
        if hasattr(status, 'signer_cert'):
            print(f"Type of signer_cert: {type(status.signer_cert)}")
            if isinstance(status.signer_cert, (bytes, bytearray)):
                print(f"Length of signer_cert bytes: {len(status.signer_cert)}")
                print(f"First few bytes: {status.signer_cert[:20]}")

        # === 5. In kết quả ===
        # pyHanko's status.summary() returns a string; use the status properties
        # (e.g. bottom_line) to determine overall validity.
        valid = bool(getattr(status, 'bottom_line', False))
        if valid:
            print("✅ Chữ ký HỢP LỆ (VALID).")
        else:
            # Fallback: if summary() reports 'INTACT...' treat as valid
            try:
                summary_str = status.summary()
                if isinstance(summary_str, str) and summary_str.startswith('INTACT'):
                    valid = True
                    print("✅ Chữ ký HỢP LỆ (VALID).")
                else:
                    print("❌ Chữ ký KHÔNG HỢP LỆ (INVALID).")
            except Exception:
                print("❌ Chữ ký KHÔNG HỢP LỆ (INVALID).")

        print("\n--- Thông tin chữ ký ---")
        print(f"Tên field: {sig_name}")

        # signed_data may be absent depending on the signature type; guard access
        if hasattr(status, 'signed_data') and status.signed_data:
            sd = status.signed_data
            signing_time = getattr(sd, 'signing_time', None)
            if signing_time:
                print(f"Ngày ký: {signing_time}")
            else:
                print("Ngày ký: (không có thông tin)")

            digest_alg = getattr(sd, 'digest_algorithm', None)
            if digest_alg:
                print(f"Thuật toán hash: {digest_alg}")
            else:
                print("Thuật toán hash: (không có thông tin)")
        else:
            print("Ngày ký: (không có thông tin)")
            print("Thuật toán hash: (không có thông tin)")
        
        # Hiển thị thông tin người ký từ chứng chỉ
        signer_cert = None
        
        # Thử lấy từ signer_infos trước (guard signed_data existence)
        if hasattr(status, 'signed_data') and hasattr(status.signed_data, 'signer_infos'):
            signer_infos = list(status.signed_data.signer_infos)
            if signer_infos and hasattr(signer_infos[0], 'signer_cert'):
                signer_cert = signer_infos[0].signer_cert

        # Nếu không có, thử lấy từ status.signer_cert
        if signer_cert is None and hasattr(status, 'signer_cert'):
            signer_cert = status.signer_cert

        # Xử lý chứng chỉ nếu có
        if signer_cert is not None:
            # Nếu là bytes, chuyển sang đối tượng asn1crypto certificate
            if isinstance(signer_cert, (bytes, bytearray)):
                try:
                    if asn1_pem.detect(signer_cert):
                        _, _, der_bytes = asn1_pem.unarmor(signer_cert)
                    else:
                        der_bytes = signer_cert
                    signer_cert = asn1_x509.Certificate.load(der_bytes)
                except Exception:
                    signer_cert = None

            # In thông tin người ký từ asn1crypto certificate
            if isinstance(signer_cert, asn1_x509.Certificate):
                try:
                    subject = signer_cert.subject.human_friendly
                    print(f"Người ký: {subject}")
                except Exception:
                    print(f"Người ký: {signer_cert.subject}")
            else:
                print("Người ký: (không đọc được thông tin)")
        else:
            print("Người ký: (không có thông tin)")
        # In thêm báo cáo chi tiết do pyHanko sinh ra
        try:
            print("\n--- Chi tiết xác thực ---")
            try:
                print(format_pretty_print_details(status))
            except Exception:
                for hdr, body in status.pretty_print_sections():
                    print(hdr)
                    print("-" * len(hdr))
                    print(body)
        except Exception:
            pass

        # Chuẩn bị output JSON/exit code
        result = {
            "file": pdf_path,
            "field": sig_name,
            "valid": valid,
            "summary": None,
            "signer_subject": None,
            "signing_time": None,
            "digest_algorithm": None,
            "validation_path": None,
            "revocation": None,
            "coverage": getattr(status, 'coverage', None),
            "modification_level": getattr(status, 'modification_level', None),
        }

        try:
            result["summary"] = status.summary()
        except Exception:
            result["summary"] = None

        # signer subject
        if isinstance(signer_cert, asn1_x509.Certificate):
            try:
                result["signer_subject"] = signer_cert.subject.human_friendly
            except Exception:
                result["signer_subject"] = str(signer_cert.subject)

        # signing_time and digest_algorithm if present
        if hasattr(status, 'signed_data') and status.signed_data:
            sd = status.signed_data
            result["signing_time"] = getattr(sd, 'signing_time', None)
            result["digest_algorithm"] = getattr(sd, 'digest_algorithm', None)

        # validation path if present
        if hasattr(status, 'validation_path') and status.validation_path is not None:
            try:
                result["validation_path"] = [p.subject.human_friendly for p in status.validation_path]
            except Exception:
                result["validation_path"] = None

        # revocation details (best-effort)
        if hasattr(status, 'revocation_details'):
            try:
                result["revocation"] = str(status.revocation_details)
            except Exception:
                result["revocation"] = None

        if output_json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))

        # Exit codes: 0 = valid, 2 = invalid, 1 = runtime error
        exit(0 if valid else 2)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"❌ Lỗi khi xác minh chữ ký: {e}")
        raise
