package plh.pkix.client.messaging.mail.reciever;

import javax.mail.MessagingException;

import plh.pkix.client.messaging.mail.reciever.strategies.ImapServer;
import plh.pkix.client.messaging.mail.repo.EmailAccount;

public class EmailAccountDataTask implements Runnable {

//	private EmailContactService emailContactService;
	private EmailAccount emailAccount;

	public void run() {
		try {
			processRun();
		} finally {
		}
	}

	private void processRun() {
		try {
			ImapServer.preprocessMailAccount(emailAccount);
//			emailContactService.saveEmailAccount(emailAccount);
		} catch (MessagingException e2) {
			return;
		}
	}

	public EmailAccountDataTask(EmailAccount emailAccount) {
//		this.emailContactService = emailContactService;
		this.emailAccount = emailAccount;
	}
}
