package org.adorys.plh.pkix.core.cmp.stores;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cert.X509CertificateHolder;

public class PrivateKeyHolder {

	private Map<ASN1OctetString, PrivateKey> privateKeyById = new HashMap<ASN1OctetString, PrivateKey>();
	
	public boolean isEmpty(){
		return privateKeyById.isEmpty();
	}

	public void addKeyPair(PrivateKey privateKey, X509CertificateHolder certificate){
		ASN1OctetString keyId = KeyIdUtils.getSubjectKeyIdentifierAsOctetString(certificate);
		privateKeyById.put(keyId, privateKey);
	}
	
	public PrivateKey getPrivateKey(ASN1OctetString keyId){
		return privateKeyById.get(keyId);
	}

	public PrivateKey getPrivateKey(X509CertificateHolder certificate){
		ASN1OctetString keyId = KeyIdUtils.getSubjectKeyIdentifierAsOctetString(certificate);
		return privateKeyById.get(keyId);
	}
}
