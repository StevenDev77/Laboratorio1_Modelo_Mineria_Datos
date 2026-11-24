import os
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Order Service")

# Vulnerabilidad Security Misconfiguration: CORS permisivo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Vulnerabilidad SSRF (OWASP A01:2025, OWASP API API7:2023, CWE-918)
# Realiza una petición GET directa hacia una URL arbitraria provista por el cliente
@app.get("/api/v1/orders/webhook-verify")
def verify_webhook(callback_url: str):
    res = requests.get(callback_url, timeout=10)
    return {"status": "ok", "body": res.text}

# Vulnerabilidad OS Command Injection (OWASP A05:2025, CWE-78)
# Concatena parámetro de entrada directamente en comando shell
@app.post("/api/v1/orders/diagnostics")
def run_diagnostic(host: str):
    cmd = "ping -c 1 " + host
    return os.system(cmd)

# Vulnerabilidad Rate Limit Absence (OWASP A06:2025, OWASP API API4:2023, CWE-770)
# Envío masivo sin middleware de throttling o limitación de tasa
@app.post("/api/v1/orders/send-sms-notification")
def send_sms_notification(phone: str, message: str):
    # No rate limiting or captcha: SMS bombing / resource exhaustion
    sms_gateway.dispatch(to=phone, content=message)
    return {"status": "dispatched"}

# Vulnerabilidad Silenciamiento de Excepciones (OWASP A10:2025, CWE-703)
@app.post("/api/v1/orders/process-payment")
def process_order_payment(order_id: int):
    try:
        payment_gateway.charge(order_id)
    except Exception:
        pass # Silently ignores critical financial failure
    return {"message": "processed"}

# Endpoint Seguro de Referencia con DTO y validación estricta
class SafeOrderDto(BaseModel):
    product_id: int
    quantity: int

@app.post("/api/v1/orders/secure-create")
def create_order_secure(dto: SafeOrderDto):
    return {"order_id": 999, "qty": dto.quantity}
