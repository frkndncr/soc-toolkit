from soc_toolkit.sdk import SOCToolkitSDK

def test_sdk_defang_refang():
    sdk = SOCToolkitSDK()
    defanged = sdk.defang("1.1.1.1")
    assert defanged == "1[.]1[.]1[.]1"
    refanged = sdk.refang(defanged)
    assert refanged == "1.1.1.1"

def test_sdk_decode():
    sdk = SOCToolkitSDK()
    res = sdk.decode_payload("powershell -enc VwByAGkAdABlAC0ASABvAHMAdAA=")
    assert res["found"] is True
