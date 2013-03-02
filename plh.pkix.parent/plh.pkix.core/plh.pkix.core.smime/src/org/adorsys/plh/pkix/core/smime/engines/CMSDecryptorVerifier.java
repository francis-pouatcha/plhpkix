package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.security.cert.X509CRL;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class CMSDecryptorVerifier {
	
	private KeyStoreWraper keyStoreWraper;
	private X509CRL crl;
	private CMSPart inputPart;
	
	private final BuilderChecker checker = new BuilderChecker(CMSDecryptorVerifier.class);
	public CMSSignedMessageValidator<CMSPart> decryptVerify() {
		checker.checkDirty()
			.checkNull(keyStoreWraper, inputPart);

		CMSPart decryptedPart = null;

		decryptedPart = new CMSDecryptor()
				.withKeyStoreWraper(keyStoreWraper)
				.withInputPart(inputPart)
				.decrypt();

		try {
			return new CMSVerifier()
				.withCrl(crl)
				.withKeyStoreWraper(keyStoreWraper)
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

	public CMSDecryptorVerifier withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}

	public CMSDecryptorVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}

	public CMSDecryptorVerifier withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}
}
