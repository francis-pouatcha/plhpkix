package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;

public class CMSDecryptorVerifier {
	
	private ContactManager contactManager;
	private CMSPart inputPart;
	
	private final BuilderChecker checker = new BuilderChecker(CMSDecryptorVerifier.class);
	public CMSSignedMessageValidator<CMSPart> decryptVerify() {
		checker.checkDirty().checkNull(contactManager, inputPart);

		CMSPart decryptedPart = null;

		decryptedPart = new CMSDecryptor()
				.withContactManager(contactManager)
				.withInputPart(inputPart)
				.decrypt();

		try {
			return new CMSVerifier()
				.withContactManager(contactManager)
				.withInputPart(decryptedPart)
				.readAndVerify();
		} catch (IOException e) {
			throw new IllegalArgumentException(e);// can not write to output stream
		} catch(RuntimeException e){
			throw e;
		} finally {
			decryptedPart.dispose();
		}
	}

	public CMSDecryptorVerifier withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}

	public CMSDecryptorVerifier withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}
}
