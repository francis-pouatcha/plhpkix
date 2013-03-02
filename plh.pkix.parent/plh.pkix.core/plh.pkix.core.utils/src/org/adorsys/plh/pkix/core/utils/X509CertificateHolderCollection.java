package org.adorsys.plh.pkix.core.utils;

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
			byte[] subjectKeyIdentifier = KeyIdUtils.readSubjectKeyIdentifierAsByteString(x509CertificateHolder);
			if(Arrays.areEqual(keyId, subjectKeyIdentifier)){
				return x509CertificateHolder;
			}
		}
		return null;
	}
	
	public X509CertificateHolder findBySubjectAndIssuerKeyId(byte[] subjectKeyId, byte[] issuerKeyId){
		if(x509CertificateHolders==null) return null;
		for (X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
			byte[] subjectKeyIdentifier = KeyIdUtils.readSubjectKeyIdentifierAsByteString(x509CertificateHolder);
			byte[] authorityKeyIdentifier = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(x509CertificateHolder);
			if(
					Arrays.areEqual(subjectKeyId, subjectKeyIdentifier) 
						&&
					Arrays.areEqual(issuerKeyId, authorityKeyIdentifier)
			){
				return x509CertificateHolder;
			}
		} 
		return null;
	}
}
