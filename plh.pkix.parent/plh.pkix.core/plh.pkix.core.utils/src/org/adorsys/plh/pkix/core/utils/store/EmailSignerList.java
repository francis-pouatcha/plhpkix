package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.i18n.ErrorBundle;

public class EmailSignerList implements ExpectedSignerList {
	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();
	
	private List<String> senders = new ArrayList<String>();
	
	
	public EmailSignerList(String[] fromHeader, String[] sender) {
		processSender(fromHeader);
		processSender(fromHeader);
	}


	@Override
	public void validateSigner(X509Certificate cert, List<ErrorBundle> errors,
			List<ErrorBundle> notifications) {
		if(senders==null || senders.isEmpty()) return;
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(cert);
		for (String senderEmail : senders) {
			for (String certEmail : subjectEmails) {
				if(StringUtils.equals(senderEmail, certEmail)) return;
			}
		}
		ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
				PlhPkixCoreMessages.SignatureValidator_wrongSigner);
		errors.add(msg);		
	}


	private void processSender(String[] fromHeader){
		if(fromHeader!=null){
			for (String from : fromHeader) {
				InternetAddress[] parsedHeader;
				try {
					parsedHeader = InternetAddress.parseHeader(from, true);
					for (InternetAddress internetAddress : parsedHeader) {
						senders.add(internetAddress.getAddress().toLowerCase());
					}
				} catch (AddressException e) {
					senders.add(from);
				}
			}
		} 
	}
	
}
