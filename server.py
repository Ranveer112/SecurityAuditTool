from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
import io
import scan

app = FastAPI()



@app.post("/audit")
async def audit_file(file: UploadFile = File(...)):
    contents = await file.read()
    result_str = scan.generate_security_report_text(contents.decode("utf-8"))
    result_io = io.BytesIO(result_str.encode("utf-8"))
    return StreamingResponse(result_io, media_type="text/plain", headers={
        "Content-Disposition": f"attachment; filename=report.txt"
    })
