package org.adorsys.plh.pkix.core.smime.engines;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;

public class SMIMEBodyPartDecryptorVerifier {

	private MimeBodyPart mimeBodyPart;
	private ContactManager contactManager;

	private final BuilderChecker checker = new BuilderChecker(
			SMIMEBodyPartDecryptorVerifier.class);
	public CMSSignedMessageValidator<MimeBodyPart> decryptAndVerify() {
		checker.checkDirty().checkNull(contactManager, mimeBodyPart);

		MimeBodyPart decryptedBodyPart = new SMIMEBodyPartDecryptor()
				.withContactManager(contactManager)
				.withMimeBodyPart(mimeBodyPart)
				.decrypt();

		return new SMIMEBodyPartVerifier()
			.withContactManager(contactManager)
			.withSignedBodyPart(decryptedBodyPart)
			.readAndVerify();
	}

	public SMIMEBodyPartDecryptorVerifier withMimeBodyPart(
			MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}
	public SMIMEBodyPartDecryptorVerifier withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
