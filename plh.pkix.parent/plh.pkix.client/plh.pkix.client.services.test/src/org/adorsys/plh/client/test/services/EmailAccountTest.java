package org.adorsys.plh.client.test.services;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;
import java.util.UUID;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import junit.framework.Assert;

import org.adorsys.plh.pkix.client.services.datatypes.EmailAccount;
import org.junit.Test;

public class EmailAccountTest {

	@Test
	public void testEmailAccount() throws JAXBException{
		JAXBContext context = JAXBContext.newInstance(EmailAccount.class);
		EmailAccount emailAccount = new EmailAccount();
		emailAccount.setAdvanced(true);
		emailAccount.setEmail("fpo@adorsys.de");
		emailAccount.setFolder("INBOX");
		emailAccount.setHost("mail.google.com");
		emailAccount.setLastImport(new Date());
		emailAccount.setLastImportComment("No comment");
		emailAccount.setLastInported(5);
		emailAccount.setLastProcessedMessageId(UUID.randomUUID().toString());
		emailAccount.setPassword("Smaple Password");
		emailAccount.setPort("922");
		emailAccount.setProtocol("smtps");
		emailAccount.setServerCertificate("Sample server certificate");
		emailAccount.setSmtpHost("mail.google.com");
		emailAccount.setSmtpPort("922");
		emailAccount.setSmtpProtocol("smtps");
		emailAccount.setUsername("fpo@adorsys.de");
		
		StringWriter writer = new StringWriter();
		Marshaller m = context.createMarshaller();
		m.marshal(emailAccount, writer);
		String EmailAccountString = writer.toString();

		System.out.println(writer.toString());		

		Unmarshaller u = context.createUnmarshaller();
		EmailAccount unmarshal = (EmailAccount) u.unmarshal(new StringReader(EmailAccountString));

		Assert.assertEquals(emailAccount, unmarshal);
		
	}
}
