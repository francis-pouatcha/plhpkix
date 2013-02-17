package plh.pkix.client.messaging.mail.repo;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import javax.mail.AuthenticationFailedException;
import javax.mail.Folder;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.ParseException;

import plh.pkix.client.messaging.mail.reciever.strategies.ImapServer;

public class EmailAccount {

	private static final String STORAGE_PREFIX_STRING = "EmailAccount";

	private String storageHandle;

	private String email;

	private String username;

	private String password;

	private String host;

	private String port = "-1";

	private String protocol= "imaps";
	
	private String folder = "INBOX";

	private String smtpPort = "-1";

	private String smtpProtocol = "smtp";

	private String smtpHost;

	private Date lastImport;

	private String lastImportComment;

	private String serverCertificate = "Always omit";
	
	private boolean advanced;

	private final List<String> imapFolders = new ArrayList<String>();
	public static final int LASTINPORTEDPOSITION = 0;
	public static final int LASTCOUNTPOSITION = 1;
	
	private String lastProcessedMessageId;

	public EmailAccount() {
		storageHandle = UUID.randomUUID().toString() + STORAGE_PREFIX_STRING;
		imapFolders.add("0");// lastInportedPosition
		imapFolders.add("0");// lastCountPosition
	}

	public EmailAccount(String email, String password) {
		this();
		this.email = email;
		this.password = password;
		try {
			ImapServer.preprocessMailAccount(this);
		} catch (ParseException e) {
			throw new IllegalStateException(e);
		}
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPort() {
		return port;
	}

	public void setPort(String port) {
		this.port = port;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getFolder() {
		return folder;
	}

	public void setFolder(String folder) {
		this.folder = folder;
	}

	public void setLastImport(Date lastImport) {
		this.lastImport = lastImport;
	}

	public String getLastImportComment() {
		return lastImportComment;
	}

	public void setLastImportComment(String lastImportComment) {
		this.lastImportComment = lastImportComment;
	}

	public String getSmtpPort() {
		return smtpPort;
	}

	public void setSmtpPort(String smtpPort) {
		this.smtpPort = smtpPort;
	}

	public String getSmtpProtocol() {
		return smtpProtocol;
	}

	public void setSmtpProtocol(String smtpProtocol) {
		this.smtpProtocol = smtpProtocol;
	}

	public String getSmtpHost() {
		return smtpHost;
	}

	public void setSmtpHost(String smtpHost) {
		this.smtpHost = smtpHost;
	}

	public String getServerCertificate() {
		return serverCertificate;
	}

	public String getStorageHandle() {
		return storageHandle;
	}

	public void setServerCertificate(String serverCertificate) {
		this.serverCertificate = serverCertificate;
	}
	@Override
	public String toString() {
		if (email != null)
			return email;
		return super.toString();
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public Date getLastImport() {
		return lastImport;
	}

	public boolean addFolder(Folder folder,
			Set<String> handledFolders) throws MessagingException {
		return handledFolders.add(folder.getFullName());
	}

	public static Store initStore(EmailAccount emailAccount) {

		Properties retrieveMailProperties = new Properties();
		ImapServer.addSSLMailProperties(retrieveMailProperties);

		Session mailSession = Session.getInstance(retrieveMailProperties);
		Store store = null;
		try {
			store = mailSession
					.getStore(emailAccount.getProtocol());
		} catch (NoSuchProviderException e) {
			emailAccount.setLastImportComment(e.getMessage());
			emailAccount.setLastImport(new Date());
//			emailContactService.saveEmailAccount(emailAccount);
			return null;
		}

		try {
			store.connect(emailAccount.getHost(),
					(emailAccount.getPort() == null ? -1 : new Integer(emailAccount
							.getPort())), emailAccount.getUsername(), emailAccount
							.getPassword());
		} catch (AuthenticationFailedException au) {
			emailAccount
					.setLastImportComment("#{msgs.MailImportAction_UserNamePwdNotCorrect}");
			emailAccount.setLastImport(new Date());
//			emailContactService.saveEmailAccount(emailAccount);
			closeStore(store);
			return null;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				emailAccount
						.setLastImportComment("#{msgs.MailImportAction_HostUnknown}");
				emailAccount.setLastImport(new Date());
//				emailContactService.saveEmailAccount(emailAccount);
				closeStore(store);
				return null;
			}
			emailAccount.setLastImportComment(e.getMessage());
			emailAccount.setLastImport(new Date());
//			emailContactService.saveEmailAccount(emailAccount);
			closeStore(store);
			return null;
		}
		return store;
	}

	public static Store reconnect(Store store,
			EmailAccount mailImportAction) {
		try {
			store.connect(mailImportAction.getHost(), (mailImportAction
					.getPort() == null ? -1 : new Integer(mailImportAction
					.getPort())), mailImportAction.getUsername(),
					mailImportAction.getPassword());
		} catch (AuthenticationFailedException au) {
			mailImportAction
					.setLastImportComment("#{msgs.MailImportAction_UserNamePwdNotCorrect}");
//			emailContactService.saveEmailAccount(mailImportAction);
			closeStore(store);
			return null;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				mailImportAction
						.setLastImportComment("#{msgs.MailImportAction_HostUnknown}");
//				emailContactService.saveEmailAccount(mailImportAction);
				closeStore(store);
				return null;
			}
			mailImportAction.setLastImportComment(e.getMessage());
//			emailContactService.saveEmailAccount(mailImportAction);
			closeStore(store);
			return null;
		}
		return store;
	}

	public static void closeStore(Store store) {
		if (store != null) {
			try {
				if (store.isConnected()) {
					store.close();
				}
			} catch (MessagingException ex) {
				// Noop
			}
		}
	}

	/**
	 * The presentation helper is an object that can be injected by a
	 * presentation layer to simplify the use of the object in a presentation
	 * framework like jsf.
	 */
	private Object clientHelper;

	public Object getClientHelper() {
		return clientHelper;
	}

	public void setClientHelper(Object clientHelper) {
		this.clientHelper = clientHelper;
	}

	public String getLastProcessedMessageId() {
		return lastProcessedMessageId;
	}

	public void setLastProcessedMessageId(String lastProcessedMessageId) {
		this.lastProcessedMessageId = lastProcessedMessageId;
	}

	public List<String> getImapFolders() {
		return imapFolders;
	}

	public int getLastInported(){
		String string = imapFolders.get(LASTINPORTEDPOSITION);
		return Integer.parseInt(string);
	}

	public int getLastCount(){
		String string = imapFolders.get(LASTCOUNTPOSITION);
		return Integer.parseInt(string);
	}
	
	public void setLastInported(int lastImported){
		imapFolders.set(LASTINPORTEDPOSITION, lastImported+"");
	}
	
	public void setLastCount(int lastCount){
		imapFolders.set(LASTCOUNTPOSITION,lastCount+"");
	}

	public boolean isAdvanced() {
		return advanced;
	}

	public void setAdvanced(boolean advanced) {
		this.advanced = advanced;
	}
}
