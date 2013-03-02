package org.adorsys.plh.pkix.core.smime.engines;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;

public class CMSSignerEncryptor {

	private CMSPart inputPart;
	private List<X509Certificate> recipientCertificates;
	
	private final BuilderChecker checker = new BuilderChecker(CMSSignerEncryptor.class);
	public CMSPart signEncrypt(PrivateKeyEntry privateKeyEntry) {
		checker.checkDirty()
			.checkNull(privateKeyEntry, inputPart,recipientCertificates)
			.checkEmpty(recipientCertificates);

		CMSPart outputPart;
		outputPart = new CMSSigner()
			.withInputPart(inputPart)
			.sign(privateKeyEntry);
		
		// encrypt the file
		try {
			return new CMSEncryptor()
				.withInputPart(outputPart)
				.withRecipientCertificates(recipientCertificates)
				.encrypt();
		} finally {
			outputPart.dispose();
		}
	}

	public CMSSignerEncryptor withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}

	public CMSSignerEncryptor withRecipientCertificates(List<X509Certificate> recipientCertificates) {
		this.recipientCertificates = recipientCertificates;
		return this;
	}
}
