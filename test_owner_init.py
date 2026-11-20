from owner_app import app, db, signer

print("Ed25519 Public Key PEM:")
pub_pem = signer.get_public_key_pem()
print(pub_pem)

lic = db.create_license(customer_id=None, license_type="Professional", duration_days=30, max_devices=1, notes="Initial Verification Test Key")
print(f"Generated test key: {lic['license_key']}")

with app.test_client() as client:
    res = client.get('/login')
    print("GET /login status:", res.status_code)
    assert res.status_code == 200

    # Test API activate
    act_res = client.post('/api/v1/license/activate', json={
        'license_key': lic['license_key'],
        'device_fingerprint': 'DEV-TEST-0001',
        'device_name': 'QA-Windows-PC'
    })
    print("POST /api/v1/license/activate status:", act_res.status_code)
    act_data = act_res.get_json()
    print("Activation response ok:", act_data.get('ok'))
    assert act_data.get('ok') is True
    assert 'signature' in act_data.get('data')

    # Test signature verification using public key
    entitlement = act_data['data']['entitlement']
    sig = act_data['data']['signature']
    is_valid = signer.verify(entitlement, sig)
    print("Cryptographic signature verified successfully?", is_valid)
    assert is_valid is True

print("ALL OWNER CONTROL CENTER CHECKS PASSED PERFECTLY!")
