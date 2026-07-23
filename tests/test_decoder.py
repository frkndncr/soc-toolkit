from soc_toolkit.decoder import PayloadDecoder

def test_defang_url():
    defanged = PayloadDecoder.defang("https://evil.com/malware")
    assert defanged == "hXXps://evil[.]com/malware"

def test_refang_url():
    refanged = PayloadDecoder.refang("hXXps://evil[.]com/malware")
    assert refanged == "https://evil.com/malware"

def test_decode_powershell():
    cmd = "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcAMgA="
    decoded = PayloadDecoder.decode_powershell(cmd)
    assert decoded["found"] is True
    assert "Write-Host" in decoded["payloads"][0]["decoded"]
