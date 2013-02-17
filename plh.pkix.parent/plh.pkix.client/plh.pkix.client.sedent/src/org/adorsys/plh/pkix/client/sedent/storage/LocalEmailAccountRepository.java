package org.adorsys.plh.pkix.client.sedent.storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.adorsys.plh.pkix.client.services.Account;
import org.adorsys.plh.pkix.client.services.datatypes.EmailAccount;
import org.adorsys.plh.pkix.client.services.repo.EmailAccountRepository;

public class LocalEmailAccountRepository implements EmailAccountRepository {
	
	private Account account;
	
	private JAXBContext context;
	
	public LocalEmailAccountRepository(Account account) {
		this.account = account;
		try {
			this.context = JAXBContext.newInstance(EmailAccount.class);
		} catch (JAXBException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public void updateEmailAcount(EmailAccount emailAccount) {
		Marshaller marshaller;
		try {
			marshaller = context.createMarshaller();
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			marshaller.marshal(emailAccount, bos);
			String fileName = EmailAccount.makeEmailAccountRelFileName(emailAccount.getEmail());
			account.deviceStoreTo(new ByteArrayInputStream(bos.toByteArray()), fileName);		
		} catch (JAXBException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public EmailAccount findEmailAccount(String emailStrict) {
		try {
			String relativeInputPath = EmailAccount.makeEmailAccountRelFileName(emailStrict);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			account.deviceLoadFrom(relativeInputPath, outputStream);
			Unmarshaller unmarshaller = context.createUnmarshaller();
			return (EmailAccount) unmarshaller.unmarshal(new ByteArrayInputStream(outputStream.toByteArray()));
		} catch (JAXBException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}
