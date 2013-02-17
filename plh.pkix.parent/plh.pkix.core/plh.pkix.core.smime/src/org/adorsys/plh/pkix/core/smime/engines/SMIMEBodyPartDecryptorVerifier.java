package org.adorsys.plh.pkix.core.smime.engines;

import java.security.KeyStore;
import java.security.cert.X509CRL;

import javax.mail.internet.MimeBodyPart;
import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;

public class SMIMEBodyPartDecryptorVerifier {

	private MimeBodyPart mimeBodyPart;
	private CallbackHandler callbackHandler;
	private KeyStore keyStore;
	private X509CRL crl;// can be null

	private final BuilderChecker checker = new BuilderChecker(
			SMIMEBodyPartDecryptorVerifier.class);
	public CMSSignedMessageValidator decryptAndVerify() {
		checker.checkDirty().checkNull(keyStore, callbackHandler, mimeBodyPart);

		MimeBodyPart decryptedBodyPart = new SMIMEBodyPartDecryptor()
				.withKeyStore(keyStore)
				.withCallbackHandler(callbackHandler)
				.withMimeBodyPart(mimeBodyPart)
				.decrypt();

		return new SMIMEBodyPartVerifier()
			.withCrl(crl)
			.withKeyStore(keyStore)
			.withSignedBodyPart(decryptedBodyPart)
			.readAndVerify();
	}

	public SMIMEBodyPartDecryptorVerifier withMimeBodyPart(
			MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}

	public SMIMEBodyPartDecryptorVerifier withCallbackHandler(
			CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}

	public SMIMEBodyPartDecryptorVerifier withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public SMIMEBodyPartDecryptorVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}
}
