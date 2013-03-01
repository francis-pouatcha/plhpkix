package org.adorsys.plh.pkix.core.cmp.message;

import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.util.Arrays;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.utils.RequestVerifier2;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.GeneralNameHolder;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;

/**
 * First check the message for conformity. In case of a conformity error,
 * the message shall be sent back to the user if possible or deleted.
 * 
 * If the message is sent back to the user, a copy should be held  for future 
 * processing. If the same message is repeated with a conformity error, the 
 * message is simply marked for deletion. The means resent occurs only one time
 * per thread. A thread is identified with the transaction id.s
 * 
 * @author francis
 *
 */
public class PkiMessageChecker {
	
	private static final String RESOURCE_NAME = CMPMessageValidatorMessages.class.getName();
	
	private KeyStoreWraper keyStoreWraper;
	
	private final BuilderChecker checker = new BuilderChecker(PkiMessageChecker.class);
	public CertificateValidatingProcessingResult<ProtectedPKIMessage> check(PKIMessage pkiMessage){
		checker.checkDirty()
			.checkNull(keyStoreWraper, pkiMessage);
		
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(pkiMessage);
		ProcessingResults<ProtectedPKIMessage> r = 
				new PkiMessageConformity()
					.withGeneralPKIMessage(generalPKIMessage)
					.check();
		CertificateValidatingProcessingResult<ProtectedPKIMessage> result = new CertificateValidatingProcessingResult<ProtectedPKIMessage>(r);
		if(result.hasError()){
			return new CertificateValidatingProcessingResult<ProtectedPKIMessage>(result);
		}
		
		ProtectedPKIMessage protectedPKIMessage = result.getReturnValue();

		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		GeneralName sender = protectedPKIMessage.getHeader().getSender();
		GeneralNameHolder senderHolder = new GeneralNameHolder(sender);
		X500Name senderX500Name = senderHolder.getX500Name();
		X509CertificateHolder senderCertificate = null;
		// first certificate if in chain must be for the sender
		if(certificates!=null && certificates.length>0){
			senderCertificate = certificates[0];
			if(!senderX500Name.equals(senderCertificate.getSubject())){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CMPMessageValidatorMessages.certificate.senderNotMatchingCertificate",
						new Object[]{senderX500Name,senderCertificate.getSubject()});
				result.addNotification(msg);
			}
		} else {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CMPMessageValidatorMessages.conformity.notCertificateSentWithMessage");
			result.addError(msg);
			return result;// stop processing, missing certificate
		}

		JcaCertStoreBuilder jcaCertStoreBuilder = new JcaCertStoreBuilder();
		for (X509CertificateHolder x509CertificateHolder : certificates) {
			jcaCertStoreBuilder = jcaCertStoreBuilder.addCertificate(x509CertificateHolder);
		}		
		CertStore certStore;
		try {
			certStore = jcaCertStoreBuilder.build();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
		PKIXParameters params = PKIXParametersFactory.makeParams(keyStoreWraper, null);

		// Validate certificate.
		List<X509CertificateHolder> signerX509CertificateHolders = Arrays.asList(senderCertificate);
		PKISignedMessageValidator signedMessageValidator = new PKISignedMessageValidator()
			.withCerts(certStore)
			.withPKIXParameters(params)
			.withSignerCertificates(signerX509CertificateHolders)
			.validate();
		
		ValidationResult validationResult;
		try {
			validationResult = signedMessageValidator.getValidationResult(senderCertificate);
			result.setValidationResult(validationResult);
			result.setCertificateHolder(senderCertificate);
			// verify request
			ProcessingResults<Boolean> verifyResult = 
					new RequestVerifier2()
						.withCertificateHolder(senderCertificate)
						.withProtectedPKIMessage(protectedPKIMessage)
						.verify();
			validationResult.getErrors().addAll(verifyResult.getErrors());
			validationResult.getNotifications().addAll(verifyResult.getNotifications());
			validationResult.setSignVerified(verifyResult.getReturnValue());
		} catch (SignedMailValidatorException e) {
			ErrorBundle errorMessage = e.getErrorMessage();
			result.addError(errorMessage);
		}
		
		return result;
	}
	public PkiMessageChecker withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}
}
