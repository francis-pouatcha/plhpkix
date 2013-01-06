package org.adorys.plh.pkix.server.cmp.core.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

public class X509CertificateHolderCollection {

	private final X509CertificateHolder[] x509CertificateHolders;

	public X509CertificateHolderCollection(
			X509CertificateHolder[] x509CertificateHolders) {
		this.x509CertificateHolders = x509CertificateHolders;
	}
	
	public X509CertificateHolder findBySubjectKeyIdentifier(byte[] keyId){
		if(x509CertificateHolders==null) return null;
		for (X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
			byte[] subjectKeyIdentifier = KeyIdUtils.getSubjectKeyIdentifierAsByteString(x509CertificateHolder);
			if(Arrays.areEqual(keyId, subjectKeyIdentifier)){
				return x509CertificateHolder;
			}
		}
		return null;
	}
	
	public X509CertificateHolder findBySubjectAndIssuerName(ASN1Encodable subjectName, ASN1Encodable issuerName){
		if(x509CertificateHolders==null) return null;
		for (X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
			if(
					subjectName.equals(x509CertificateHolder.getSubject()) 
						&&
					issuerName.equals(x509CertificateHolder.getIssuer())
			){
				return x509CertificateHolder;
			}
		}
		return null;
	}

	public X509CertificateHolder findBySubjectName(ASN1Encodable subjectName){
		if(x509CertificateHolders==null) return null;
		for (X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
			if(subjectName.equals(x509CertificateHolder.getSubject()))
			{
				return x509CertificateHolder;
			}
		}
		return null;
	}
}
