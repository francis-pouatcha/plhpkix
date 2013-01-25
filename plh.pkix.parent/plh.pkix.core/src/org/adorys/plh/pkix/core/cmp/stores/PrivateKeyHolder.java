package org.adorys.plh.pkix.core.cmp.stores;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class PrivateKeyHolder {

	private static final Map<X500Name, PrivateKeyHolder> instances = new HashMap<X500Name, PrivateKeyHolder>();

	private Map<ASN1OctetString, PrivateKey> privateKeyById = new HashMap<ASN1OctetString, PrivateKey>();
	
	public static PrivateKeyHolder getInstance(X500Name role){
		PrivateKeyHolder privateKeyHolder = instances.get(role);
		if(privateKeyHolder==null){
			privateKeyHolder = new PrivateKeyHolder();
			instances.put(role, privateKeyHolder);
		}
		return privateKeyHolder;
	}

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
