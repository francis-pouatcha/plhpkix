package org.adorsys.plh.pkix.core.smime.engines;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;

public class SMIMEBodyPartEncryptor {

	private MimeBodyPart mimeBodyPart;
	private List<X509Certificate> recipientX509Certificates = new ArrayList<X509Certificate>();

	private final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartEncryptor.class);
	public MimeBodyPart encrypt() throws SMIMEException, MessagingException {
		checker.checkDirty().checkNull(mimeBodyPart, recipientX509Certificates)
				.checkEmpty(recipientX509Certificates);

		SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
		for (X509Certificate recipientX509Certificate : recipientX509Certificates) {
			try {
				encrypter
						.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
								recipientX509Certificate)
								.setProvider(ProviderUtils.bcProvider));
			} catch (CertificateEncodingException e) {
				throw new IllegalStateException(e);
			}
		}

		MimeBodyPart encryptedBodyPart;
		try {
			encryptedBodyPart = encrypter.generate(mimeBodyPart,
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC)
							.setProvider(ProviderUtils.bcProvider).build());
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}

		return encryptedBodyPart;
	}

	public SMIMEBodyPartEncryptor withMimeBodyPart(MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}

	public SMIMEBodyPartEncryptor withRecipientX509Certificates(
			List<X509Certificate> recipientX509Certificates) {
		this.recipientX509Certificates = recipientX509Certificates;
		return this;
	}
}
