from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import os, tempfile, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.scanner import ScannerEngine
from core.yara_scanner import YaraScanner

app = FastAPI(title="Antivirus Server API")
config = {"cuarentena": "/tmp/server_cuarentena", "max_firmas": 100000}
engine = ScannerEngine(config)
yara = YaraScanner()

class ScanResponse(BaseModel):
    filename: str
    infected: bool
    reason: str

@app.post("/scan", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        infected, reason = engine.scan_file(tmp_path)
        if not infected:
            yara_inf, yara_reason = yara.scan_file(tmp_path)
            if yara_inf:
                infected, reason = True, yara_reason
        os.unlink(tmp_path)
        return ScanResponse(filename=file.filename, infected=infected, reason=reason)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
