package org.adorsys.plh.pkix.core.smime.engines;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.mail.smime.SMIMEException;

public class SMIMEBodyPartSignerEncryptor {
	private X500Name issuerName;
	private MimeBodyPart mimeBodyPart;
	private List<X509Certificate> recipientX509Certificates = new ArrayList<X509Certificate>();
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartSignerEncryptor.class);
	public MimeBodyPart signEncrypt(PrivateKeyEntry senderPrivateKeyEntry) throws
			SMIMEException, MessagingException {
		
		checker.checkDirty()
			.checkNull(senderPrivateKeyEntry,issuerName,mimeBodyPart,
					recipientX509Certificates)
			.checkEmpty(recipientX509Certificates);

		MimeBodyPart signedBodyPart = new SMIMEBodyPartSigner()
			.withIssuerName(issuerName)
			.withMimeBodyPart(mimeBodyPart)
			.sign(senderPrivateKeyEntry);
		signedBodyPart.setHeader("Content-Transfer-Encoding", "binary");
		
		return new SMIMEBodyPartEncryptor()
			.withRecipientX509Certificates(recipientX509Certificates)
			.withMimeBodyPart(signedBodyPart)
			.encrypt();
	}

	public SMIMEBodyPartSignerEncryptor withIssuerName(X500Name issuerName) {
		this.issuerName = issuerName;
		return this;
	}
	public SMIMEBodyPartSignerEncryptor withMimeBodyPart(MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}
	public SMIMEBodyPartSignerEncryptor withRecipientX509Certificates(
			List<X509Certificate> recipientX509Certificates) {
		this.recipientX509Certificates = recipientX509Certificates;
		return this;
	}
}
