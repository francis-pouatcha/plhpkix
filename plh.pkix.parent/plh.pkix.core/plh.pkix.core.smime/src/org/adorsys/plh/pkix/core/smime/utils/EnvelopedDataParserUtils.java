package org.adorsys.plh.pkix.core.smime.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;

public class EnvelopedDataParserUtils {

	public static List<RecipientInformation> getRecipientInfosCollection(CMSEnvelopedDataParser cmsEnvelopedDataParser){
		RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();		
        @SuppressWarnings("rawtypes")
		Collection recipientsColection = recipients.getRecipients();
        List<RecipientInformation> recipientInfoList = new ArrayList<RecipientInformation>();
        for (Object object : recipientsColection) {
        	recipientInfoList.add((RecipientInformation) object);
        }
		return recipientInfoList;
	}
	
	public static CMSEnvelopedDataParser parseData(CMSPart inputPart){
		try {
			InputStream newInputStream = inputPart.newInputStream();
			return new CMSEnvelopedDataParser(newInputStream);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public static SMIMEEnvelopedParser parseData(MimeBodyPart mimeBodyPart){
		try {
			return new SMIMEEnvelopedParser(mimeBodyPart);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		}
		
	}
	
	public static CMSEnvelopedDataParser parseData(InputStream inputStream){
		try {
			return new CMSEnvelopedDataParser(inputStream);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}		
	}
}
