package org.adorsys.plh.pkix.core.cmp.message;

import java.security.KeyStore;
import java.security.cert.PKIXCertPathValidatorResult;

import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.GeneralNameHolder;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.adorsys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.x509.PKIXCertPathReviewer;

/**
 * Generic message processor. Load and verify the message for 
 * formal correctness and integrity. Throw an {@link IllegalStateException}
 * if the message is malformed of modified. 
 * 
 * @author francis
 *
 */
public class PkiMessageChecker {
	
	private PKIXCertPathReviewer pathReviewer;
	private KeyStore keyStore;
	
	private final BuilderChecker checker = new BuilderChecker(PkiMessageChecker.class);
	public HttpResponse check(GeneralPKIMessage generalPKIMessage){
		
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		GeneralName sender = protectedPKIMessage.getHeader().getSender();
		GeneralNameHolder senderHolder = new GeneralNameHolder(sender);
		X509CertificateHolder senderCertificate = null;
		// first certificate if in chain must be for the sender
		if(certificates!=null && certificates.length>0){
			senderCertificate = certificates[0];
			GeneralNameHolder
			if(senderCertificate.getSubject())
		}

		protectedPKIMessage.g
		
        CMSSignedMessageValidator<?> signedMessageValidator = new CMSSignedMessageValidator<Object>();
		
		keyStore.getCertificateAlias(cert);
		
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(X500Name.getInstance(sender.getName()));

		if(senderCertificate==null)return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, "Missing sender certificate");

		HttpResponse verifiedRequest = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(verifiedRequest.getStatusLine().getStatusCode()!=HttpStatus.SC_OK)return verifiedRequest;
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}
	public PkiMessageChecker withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}
}
