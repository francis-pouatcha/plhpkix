package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.utils.EnvelopedDataParserUtils;
import org.adorsys.plh.pkix.core.smime.utils.RecipientAndRecipientInfo;
import org.adorsys.plh.pkix.core.smime.utils.RecipientSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;

public class CMSDecryptor {
	private ContactManager contactManager;
	private CMSPart inputPart;
	
	private final BuilderChecker checker = new BuilderChecker(CMSDecryptor.class);
	public CMSPart decrypt() {

		checker.checkDirty().checkNull(contactManager,inputPart);
		
		CMSEnvelopedDataParser cmsEnvelopedDataParser = EnvelopedDataParserUtils.parseData(inputPart);
		
		List<RecipientInformation> recipientInfoList = EnvelopedDataParserUtils.getRecipientInfosCollection(cmsEnvelopedDataParser);
        
        RecipientAndRecipientInfo recipientAndRecipientInfo = new RecipientSelector()
        	.withContactManager(contactManager)
        	.withRecipientInfosColection(recipientInfoList)
        	.select();
        
        InputStream encrryptedContentStream = null;
        try {
        	CMSTypedStream contentStream = recipientAndRecipientInfo.getRecipientInformation()
        			.getContentStream(recipientAndRecipientInfo.getRecipient());						
        	encrryptedContentStream = contentStream.getContentStream();
        	return CMSPart.instanceFrom(encrryptedContentStream);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {// can not read content stream
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(encrryptedContentStream);
		}
	}
	
	public CMSDecryptor withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
	public CMSDecryptor withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}
}
