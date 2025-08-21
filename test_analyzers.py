from src.vulnscan import analyze_headers

class DummyResp:
    def __init__(self, headers):
        self.headers = headers

def test_reports_missing_critical_headers():
    findings = analyze_headers(DummyResp(headers={}))
    keys = {f.key for f in findings}
    assert "Content-Security-Policy" in keys
    assert "Strict-Transport-Security" in keys

def test_valid_x_content_type_options():
    findings = analyze_headers(DummyResp(headers={"X-Content-Type-Options": "wrong"}))
    assert any(f.key=="X-Content-Type-Options" and not f.ok for f in findings)

def test_cookie_flags_ok():
    headers = {"Set-Cookie": "sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict"}
    findings = analyze_headers(DummyResp(headers=headers))
    assert not any(f.key.startswith("Cookie:") and not f.ok for f in findings)
