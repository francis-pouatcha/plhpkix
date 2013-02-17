package plh.pkix.client.messaging.mail.reciever.strategies;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.ParseException;
import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.lang3.StringUtils;

import plh.pkix.client.messaging.mail.repo.EmailAccount;
import plh.pkix.client.messaging.mail.utils.MailAddress;
import plh.pkix.client.messaging.mail.utils.SimpleSSLSocketFactory;

public enum ImapServer {

	ADORSYS_DE("adorsys.de", "mail.adorsys.de", "465", "mail.adorsys.de", "993"), 
	ADORSYS_COM(
			"adorsys.com", "mail.adorsys.com", "465", "mail.adorsys.com", "993"), 
	AOL(
			"aol.com", "smtp.aol.com", "465", "imap.aol.com", "993"), BELLSOUTH(
			"bellsouth.net", "smtp.bellsouth.net", "465", "mail.bellsouth.net",
			"993"), CURRYSIMPLE("currysimple.com", "smtp.currysimple.com",
			"465", "imap.currysimple.com", "993"), GACCSOUTH("gaccsouth.com",
			"smtp.gaccsouth.com", "465", "mail.gaccsouth.com", "993"), GERMANHEALTHPLANS(
			"germanhealthplans.com", "smtp.germanhealthplans.com", "465",
			"imap.germanhealthplans.com", "993"), GMX_DE("gmx.de",
			"mail.gmx.de", "465", "imap.gmx.de", "993"), GMX_COM("gmx.com",
			"mail.gmx.com", "465", "imap.gmx.com", "993"), GMAIL("gmail.com",
			"smtp.gmail.com", "465", "imap.gmail.com", "993"), GOOGLE_MAIL(
			"googlemail.com", "smtp.googlemail.com", "465",
			"imap.googlemail.com", "993"), HOTMAIL("hotmail.com",
			"smtp.hotmail.com", "465", "mail.hotmail.com", "993"), MSN(
			"msn.com", "smtp.msn.com", "465", "mail.msn.com", "993"), PARAMOUNTFINANCIALGRP(
			"paramountfinancialgrp.com", "smtp.paramountfinancialgrp", "465",
			"imap.paramountfinancialgrp.com", "993"), SIMPAQ("simpaq.com",
			"smtp.simpaq", "465", "imap.simpaq.com", "993"), WEB_DE("web.de",
			"smtp.web.de", "465", "imap.web.de", "993"), 
			YAHOO("yahoo.com",
			"smtp.mail.yahoo.com", "465", "imap.mail.yahoo.com", "993"), YAHOOFR(
			"yahoo.fr", "smtp.yahoo.fr", "465", "imap.yahoo.fr", "993");

	private String serverName;

	private String smtpServerAddr;

	private String smtpServerPort;

	private String imapServerAddr;

	private String imapServerPort;

	private ImapServer(String serverName, String smtpServerAddr,
			String smtpServerPort, String imapServerAddr, String imapServerPort) {
		this.serverName = serverName;
		this.smtpServerAddr = smtpServerAddr;
		this.smtpServerPort = smtpServerPort;
		this.imapServerAddr = imapServerAddr;
		this.imapServerPort = imapServerPort;
	}

	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	public String getSmtpServerAddr() {
		return smtpServerAddr;
	}

	public void setSmtpServerAddr(String smtpServerAddr) {
		this.smtpServerAddr = smtpServerAddr;
	}

	public String getSmtpServerPort() {
		return smtpServerPort;
	}

	public void setSmtpServerPort(String smtpServerPort) {
		this.smtpServerPort = smtpServerPort;
	}

	public String getImapServerAddr() {
		return imapServerAddr;
	}

	public void setImapServerAddr(String imapServerAddr) {
		this.imapServerAddr = imapServerAddr;
	}

	public String getImapServerPort() {
		return imapServerPort;
	}

	public void setImapServerPort(String imapServerPort) {
		this.imapServerPort = imapServerPort;
	}

	public static void preprocessMailAccount(EmailAccount emailAccount)
			throws ParseException {
		String email = emailAccount.getEmail();
		if (email == null)
			return;
		InternetAddress internetAddress = new InternetAddress(email);
		MailAddress mailAddress = new MailAddress(internetAddress);
		String host = mailAddress.getHost();
		ImapServer server = null;
		ImapServer[] values = ImapServer.values();
		for (ImapServer imapServer : values) {
			if (imapServer.getServerName().equals(host)) {
				server = imapServer;
				break;
			}
		}
		String imapHost = emailAccount.getHost();
		String imapHostTest = "imap." + host;
		String smtpHostTest = "smtp." + host;
		String mailHostTest = "mail." + host;
		if (StringUtils.isBlank(imapHost)) {
			if (server != null) {
				emailAccount.setHost(server.getImapServerAddr());
				emailAccount.setPort(server.getImapServerPort());
			} else {
				// Validate host before setting
				if (testImapHost(imapHostTest)) {
					emailAccount.setHost(imapHostTest);
				} else if (testImapHost(mailHostTest)) {
					emailAccount.setHost(mailHostTest);
				} else {
					emailAccount.setAdvanced(true);
				}
			}
		}
		String smtpHost = emailAccount.getSmtpHost();
		if (StringUtils.isBlank(smtpHost)) {
			if (server != null) {
				emailAccount.setSmtpHost(server.getSmtpServerAddr());
				emailAccount.setSmtpPort(server.getSmtpServerPort());
			} else {
				// Validate host before setting
				if (testSmtpHost(smtpHostTest)) {
					emailAccount.setSmtpHost(smtpHostTest);
				} else if (testSmtpHost(mailHostTest)) {
					emailAccount.setSmtpHost(mailHostTest);
				} else {
					emailAccount.setAdvanced(true);
				}
			}
		}
	}

	private static boolean testImapHost(String imapHostTest) {
		try {
			InetAddress.getByName(imapHostTest).isReachable(3000);
		} catch (UnknownHostException e) {
			return false;
		} catch (IOException e) {
			return checkImapHost(imapHostTest, -1);
		}
		return true;
	}

	private static boolean testSmtpHost(String host) {
		try {
			InetAddress.getByName(host).isReachable(3000);
		} catch (UnknownHostException e) {
			return false;
		} catch (IOException e) {
			return checkSmtpHost(host, -1);
		}
		return true;
	}
	
	public static boolean checkImapHost(String host, int port) {
		Properties properties = new Properties();
		addSSLMailProperties(properties);
		Session instance = Session.getInstance(properties);
		Store store = null;

		try {
			store = instance.getStore("imaps");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(
					"IMAP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		}
		try {
			store.connect(host, 993, "mario.bastler.x24", "mario1590");
		} catch (AuthenticationFailedException au) {
			return true;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return true;
			}
		}
		return true;
	}

	
	public static boolean checkSmtpHost(String host, int port) {
		Properties properties = new Properties();
		properties.put("mail.smtp.host", host);
		properties.put("mail.smtp.port", port);
		addSSLMailProperties(properties);
		Session session = Session.getDefaultInstance(properties, null);
		try {
			session.getTransport().connect("mario.bastler.x24", "mario1590");
		} catch (NoSuchProviderException e) {
			return false;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return true;
			}
		} finally {
			try {
				session.getTransport().close();
			} catch (NoSuchProviderException e) {

			} catch (MessagingException e) {

			}
		}
		return false;

	}	
	
	public static void addSSLMailProperties(final Properties properties) {
		// set this session up to use SSL for IMAP connections
		properties.setProperty("mail.smtp.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		properties.setProperty("mail.imaps.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		properties.setProperty("mail.pop3s.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		// don't fallback to normal IMAP connections on failure.
		properties.setProperty("mail.smtp.socketFactory.fallback", "false");
		properties.setProperty("mail.imaps.socketFactory.fallback", "false");
		properties.setProperty("mail.pop3s.socketFactory.fallback", "false");
	}

	public static boolean checkImapHost(EmailAccount emailAccount) {
		Properties properties = new Properties();
		addSSLMailProperties(properties);
		Session instance = Session.getInstance(properties);
		Store store = null;

		try {
			store = instance.getStore("imaps");
			emailAccount.setProtocol("imaps");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("IMAP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		}
		try {
			store.connect(emailAccount.getHost(), 993, "mario.bastler.x24", "mario1590");
		} catch (AuthenticationFailedException au) {
			emailAccount.setPort("993");
			return true;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				emailAccount.setLastImportComment(UnknownHostException.class.getName());
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return false;
			}
			return false;
		}
		return true;
	}	
	

	public static boolean checkSmtpHost(EmailAccount emailAccount) {
		Properties properties = new Properties();
		properties.put("mail.smtp.host", emailAccount.getSmtpHost());
//		properties.put("mail.smtp.port", emailAccount.getSmtpPort());
		addSSLMailProperties(properties);
		Session session = Session.getDefaultInstance(properties, null);
		try {
			session.getTransport("smtp").connect("mario.bastler.x24", "mario1590");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("SMTP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return false;
			}
			return false;
		} finally {
			try {
				session.getTransport().close();
			} catch (NoSuchProviderException e) {

			} catch (MessagingException e) {

			}
		}
		return true;
	}	
	



	public static boolean checkPop3Host(EmailAccount emailAccount) {
		Properties properties = new Properties();
		addSSLMailProperties(properties);
		Session instance = Session.getInstance(properties);
		Store store = null;

		try {
			store = instance.getStore("pop3s");
			emailAccount.setProtocol("pop3s");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("POP3_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		}
		try {
			store.connect(emailAccount.getHost(), -1, "mario.bastler.x24", "mario1590");
		} catch (AuthenticationFailedException au) {
			emailAccount.setPort("-1");
			return true;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				emailAccount.setLastImportComment(UnknownHostException.class.getName());
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return false;
			}
			return false;
		}
		return true;
	}
}
