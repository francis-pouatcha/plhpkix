package org.adorsys.plh.pkix.core.smime.engines;

import java.security.cert.X509CRL;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class SMIMEBodyPartDecryptorVerifier {

	private MimeBodyPart mimeBodyPart;
	private KeyStoreWraper keyStoreWraper;
	private X509CRL crl;// can be null

	private final BuilderChecker checker = new BuilderChecker(
			SMIMEBodyPartDecryptorVerifier.class);
	public CMSSignedMessageValidator<MimeBodyPart> decryptAndVerify() {
		checker.checkDirty().checkNull(keyStoreWraper, mimeBodyPart);

		MimeBodyPart decryptedBodyPart = new SMIMEBodyPartDecryptor()
				.withKeyStoreWraper(keyStoreWraper)
				.withMimeBodyPart(mimeBodyPart)
				.decrypt();

		return new SMIMEBodyPartVerifier()
			.withCrl(crl)
			.withKeyStoreWraper(keyStoreWraper)
			.withSignedBodyPart(decryptedBodyPart)
			.readAndVerify();
	}

	public SMIMEBodyPartDecryptorVerifier withMimeBodyPart(
			MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}

	public SMIMEBodyPartDecryptorVerifier withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}

	public SMIMEBodyPartDecryptorVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}
}
