# Baitap_BaoMatThongTin_ChuKy
**Họ và tên: Nguyễn Thị Kim Huệ**  
**MSSV     :K225480106026**   
**Lớp      :K58KTP**   
**MÔ TẢ CHUNG**  
Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác thực chữ ký số trong file PDF.   
Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib)  
**CÁC YÊU CẦU CỤ THỂ**  
**1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)**
- Mô tả ngắn gọn: Catalog, Pages tree, Page object, Resources, Content streams, XObject, AcroForm, Signature field (widget), Signature dictionary (/Sig), 
/ByteRange, /Contents, incremental updates, và DSS (theo PAdES).
- Liệt kê object refs quan trọng và giải thích vai trò của từng object trong lưu/truy xuất chữ ký.
- Đầu ra: 1 trang tóm tắt + sơ đồ object (ví dụ: Catalog → Pages → Page → /Contents; Catalog → /AcroForm → SigField → SigDict).
  
**2) Thời gian ký được lưu ở đâu?**
- Nêu tất cả vị trí có thể lưu thông tin thời gian:
 + /M trong Signature dictionary (dạng text, không có giá trị pháp lý).
 + Timestamp token (RFC 3161) trong PKCS#7 (attribute timeStampToken).
 + Document timestamp object (PAdES).
 + DSS (Document Security Store) nếu có lưu timestamp và dữ liệu xác minh.
- Giải thích khác biệt giữa thông tin thời gian /M và timestamp RFC3161.
  
**3) Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)**
- Viết script/code thực hiện tuần tự:
 1. Chuẩn bị file PDF gốc.
 2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
 3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
 4. Tính hash (SHA-256/512) trên vùng ByteRange.   
 5. Tạo PKCS#7/CMS detached hoặc CAdES:
 - Include messageDigest, signingTime, contentType.
 - Include certificate chain.
 - (Tùy chọn) thêm RFC3161 timestamp token.
 6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
 7. Ghi incremental update.
 8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.
- Phải nêu rõ: hash alg, RSA padding, key size, vị trí lưu trong PKCS#7.
- Đầu ra: mã nguồn, file PDF gốc, file PDF đã ký.
**4) Các bước xác thực chữ ký trên PDF đã ký**
- Các bước kiểm tra:
 1. Đọc Signature dictionary: /Contents, /ByteRange.
 2. Tách PKCS#7, kiểm tra định dạng.
 3. Tính hash và so sánh messageDigest.
 4. Verify signature bằng public key trong cert.
 5. Kiểm tra chain → root trusted CA.
 6. Kiểm tra OCSP/CRL.
 7. Kiểm tra timestamp token.
 8. Kiểm tra incremental update (phát hiện sửa đổi).
- Nộp kèm script verify + log kiểm thử.
  
**BÀI LÀM**  
**1.Cấu trúc PDF liên quan chữ ký (Nghiên cứu)**  
<img width="599" height="726" alt="image" src="https://github.com/user-attachments/assets/fc852f8c-ddf7-4ee1-bc7a-f8e8422bc2d2" />   
<img width="739" height="243" alt="image" src="https://github.com/user-attachments/assets/12dc350d-9c54-40a3-b053-1441885c63d4" />   

Object refs quan trọng
<img width="812" height="295" alt="image" src="https://github.com/user-attachments/assets/7a3431d4-bacc-49c5-a839-e23f3923caae" />    

 Sơ đồ quan hệ object (simplified)  
<img width="599" height="427" alt="image" src="https://github.com/user-attachments/assets/327e5294-2cc7-46bb-a2f9-44166977370b" />   

**2. Thời gian ký trong PDF**  
 Các vị trí có thể lưu thời gian ký   
 <img width="739" height="430" alt="image" src="https://github.com/user-attachments/assets/7bf0819d-4d82-470d-b46f-aa3cfd7adfed" />   

 Khác biệt giữa /M và timestamp RFC 3161  
 <img width="745" height="345" alt="image" src="https://github.com/user-attachments/assets/37531f26-c236-46bb-b39b-65450d3eca60" />   

 **Kết luận**
Quy trình trên mô phỏng đúng cách mà phần mềm ký số thực hiện trên
file PDF:
Xác định vùng dữ liệu hợp lệ bằng /ByteRange
Tạo chữ ký số PKCS#7 detached
Chèn chữ ký vào /Contents
Lưu file theo incremental update để đảm bảo tính toàn vẹn, không
thể thay đổi nội dung đã ký.









