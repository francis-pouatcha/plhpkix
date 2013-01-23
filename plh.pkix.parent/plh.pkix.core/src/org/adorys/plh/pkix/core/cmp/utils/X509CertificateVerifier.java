package org.adorys.plh.pkix.core.cmp.utils;

import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public abstract class X509CertificateVerifier {

    public static HttpResponse verifyRequest(Date date, X509CertificateHolder subjectCertHolder, X509CertificateHolder issuerCertHolder){

		if(!subjectCertHolder.isValidOn(date))
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, "Expired certificate");
			

		if(!issuerCertHolder.isValidOn(date)) 
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, "Expired signer certificate");
    	
		Provider provider = PlhCMPSystem.getProvider();
    	
		X509Certificate issuerCert = V3CertificateUtils.getCertificate(issuerCertHolder, provider);

        ContentVerifierProvider verifierProvider;
		try {
			verifierProvider = new JcaContentVerifierProviderBuilder()
				.setProvider(provider).build(issuerCert.getPublicKey());
		} catch (OperatorCreationException e) {
			return ResponseFactory.create(HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
		}

		boolean verified;
		try {
			verified = subjectCertHolder.isSignatureValid(verifierProvider);
		} catch (CertException e) {
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, e.getMessage());
		}
		if(!verified){
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, "Invalid certficate");
		}
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
    }

    public static boolean isSelfSignedBy(X500Name subject, X509CertificateHolder certificate){
		return certificate.getSubject().equals(subject) && certificate.getSubject().equals(certificate.getIssuer());
	}
}
