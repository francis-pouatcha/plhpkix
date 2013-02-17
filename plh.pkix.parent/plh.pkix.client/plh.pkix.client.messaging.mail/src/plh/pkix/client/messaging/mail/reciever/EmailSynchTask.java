package plh.pkix.client.messaging.mail.reciever;

import java.util.Date;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.FetchProfile;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.InternetAddress;

import plh.pkix.client.messaging.mail.repo.EmailAccount;

public class EmailSynchTask implements Runnable {

	private EmailAccount emailAccount;

	public void run() {
		try {
			Store store = EmailAccount.initStore(emailAccount);
			if (store==null){
				return;
			}
			Folder folder = getMainFolder(store);
			processRun(folder);
			EmailAccount.closeStore(store);			
		} finally {
//			LoginTicket.setActiveLogin(oldTicket);
		}
	}
	
	public Folder getMainFolder(Store store){
		Folder folder;
		try {
			folder = store.getFolder(emailAccount.getFolder());
		} catch (MessagingException e) {
			emailAccount.setLastImportComment(e.getMessage());
			emailAccount.setLastImport(new Date());
//			emailContactService.saveEmailAccount(emailAccount);
			return null;
		}
		return folder;
	}

	private void processRun(Folder folder) {

		int messageCount;
		try {
			folder.open(Folder.READ_ONLY);
			messageCount = folder.getMessageCount();
		} catch (MessagingException e2) {
			emailAccount.setLastImportComment(e2.getMessage());
			emailAccount.setLastImport(new Date());
//			emailContactService.saveEmailAccount(emailAccount);
			return;
		}
		emailAccount.setLastCount(messageCount);
//		emailContactService.saveEmailAccount(emailAccount);
		
		int fetchSize = 5000;
		int start = 1;
		int end = messageCount;
		if(end>fetchSize){
			end = fetchSize;
		}
		while (start < messageCount){
			// managing iterations
			Message[] messages;
			try {
				messages = folder.getMessages(start, end);
			} catch (MessagingException e2) {
				return;
			}
	
			FetchProfile headerProfile = new FetchProfile();
			// headerProfile.add(FetchProfile.Item.FLAGS);
			headerProfile.add(FetchProfile.Item.ENVELOPE);
	
			try {
				folder.fetch(messages, headerProfile);
			} catch (MessagingException e1) {
				return;
			}
			int length = messages.length;
			for (int j = length - 1; j >= 0; j--) {
				Message message = messages[j];
				processMessage(message);
			}
			
			start = end;
			end = end + fetchSize;
			if(end>messageCount) end=messageCount;			
		}
	}

	public EmailSynchTask(EmailAccount emailAccount) {
//		this.emailContactService = emailContactService;
		this.emailAccount = emailAccount;
	}

	private void processMessage(Message message) {
		try {
			Address[] allRecipients = message.getAllRecipients();
			if (allRecipients!=null){
				for (Address address : allRecipients) {
					newEmailContact(address);
				}
			}
		} catch (MessagingException e) {
//			LOG.error(e.getMessage(), e);
		}
		try {
			Address[] from = message.getFrom();
			if(from!=null){
				for (Address address : from) {
					newEmailContact(address);
				}
			}
		} catch (MessagingException e) {
//			LOG.error(e.getMessage(), e);
		}
	}

	private void newEmailContact(Address address) {
		if (address == null)
			return;
		InternetAddress internetAddress = (InternetAddress) address;
		String personal = internetAddress.getPersonal();
		String emailAddress = internetAddress.getAddress();
//		List<LoginObject> found = emailContactService.findByEmail(emailAddress);
//		if (!found.isEmpty())
//			return;
//		emailContactService.newEmailContact(emailAddress, personal);
	}

	private Properties retrieveMailProperties(EmailAccount action) {
		Properties properties = new Properties();
		return properties;
	}

	public void importMail(EmailAccount action) {
		Properties retrieveMailProperties = retrieveMailProperties(action);
		Session instance = Session.getInstance(retrieveMailProperties);
		Folder inboxFolder = null;
		Store store = null;
		try {
			store = instance.getStore(action.getProtocol());
			store.connect(action.getHost(), (action.getPort() == null ? -1
					: new Integer(action.getPort())), action.getUsername(),
					action.getPassword());
			Folder defaultFolder = store.getDefaultFolder();
			inboxFolder = defaultFolder.getFolder(action.getFolder());
			inboxFolder.open(Folder.READ_ONLY);
			Message[] messages = inboxFolder.getMessages();

			FetchProfile headerProfile = new FetchProfile();
			headerProfile.add(FetchProfile.Item.ENVELOPE);
			inboxFolder.fetch(messages, headerProfile);
			for (Message message : messages) {
				processMessage(message);
			}
		} catch (MessagingException ex) {
//			LOG.warn(ex);
		} finally {
			if (inboxFolder != null) {
				try {
					inboxFolder.close(false);
				} catch (MessagingException ex) {
//					LOG.warn(ex);
				}
			}
			if (store != null) {
				try {
					store.close();
				} catch (MessagingException ex) {
//					LOG.warn(ex);
				}
			}
		}
	}

}
