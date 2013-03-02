package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.util.List;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.utils.EnvelopedDataParserUtils;
import org.adorsys.plh.pkix.core.smime.utils.RecipientAndRecipientInfo;
import org.adorsys.plh.pkix.core.smime.utils.RecipientSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class SMIMEBodyPartDecryptor {
	private KeyStoreWraper keyStoreWraper;
	private MimeBodyPart mimeBodyPart;
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartDecryptor.class);
	public MimeBodyPart decrypt() {

		checker.checkDirty()
			.checkNull(keyStoreWraper,mimeBodyPart);
		
		SMIMEEnvelopedParser m=EnvelopedDataParserUtils.parseData(mimeBodyPart);

		List<RecipientInformation> recipientInfosCollection = EnvelopedDataParserUtils.getRecipientInfosCollection(m);
		RecipientAndRecipientInfo recipientAndRecipientInfo = new RecipientSelector()
			.withKeyStoreWraper(keyStoreWraper)
			.withRecipientInfosColection(recipientInfosCollection)
			.select();
		

		RecipientInformation recipientInformation = recipientAndRecipientInfo.getRecipientInformation();
		Recipient recipient = recipientAndRecipientInfo.getRecipient();
        try {
			return SMIMEUtil.toMimeBodyPart(recipientInformation.getContentStream(recipient));
		} catch (SMIMEException e) {
			throw new SecurityException(e);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public SMIMEBodyPartDecryptor withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}

	public SMIMEBodyPartDecryptor withMimeBodyPart(MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}
}
