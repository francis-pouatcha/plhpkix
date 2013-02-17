package plh.pkix.client.messaging.mail.utils;

import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;

public class PloohSMTPAuthenticator extends Authenticator {

	private String userName;
	private String password;

	public PloohSMTPAuthenticator(String userName, String password) {
		super();
		this.userName = userName;
		this.password = password;
	}

	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication(userName, password);
	}
}
