package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;

public class CMSPWDStreamDecryptor {
	private InputStream inputStream;
	
	private final BuilderChecker checker = new BuilderChecker(CMSPWDStreamDecryptor.class);
	public InputStream toDecryptingInputStream(char[] password) {

		checker.checkDirty()
			.checkNull(inputStream, password);
		
		CMSEnvelopedDataParser cmsEnvelopedDataParser;
		try {
			cmsEnvelopedDataParser = new CMSEnvelopedDataParser(inputStream);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}

		RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();		

        @SuppressWarnings("rawtypes")
		Collection recipientsColection = recipients.getRecipients();
        RecipientInformation recipient = (RecipientInformation) recipientsColection.iterator().next();
        
        InputStream encrryptedContentStream = null;
        try {
        	CMSTypedStream contentStream = recipient.getContentStream(new JcePasswordEnvelopedRecipient(password));
        	return contentStream.getContentStream();
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {// can not read content stream
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(encrryptedContentStream);
		}
	}
	
	public CMSPWDStreamDecryptor withInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
		return this;
	}

}
