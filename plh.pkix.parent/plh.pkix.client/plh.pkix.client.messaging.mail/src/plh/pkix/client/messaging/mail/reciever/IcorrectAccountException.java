package plh.pkix.client.messaging.mail.reciever;

import javax.mail.MessagingException;

public class IcorrectAccountException extends Exception {

	private static final long serialVersionUID = -88248230575201012L;
	public IcorrectAccountException(MessagingException e) {
		super(e);
	}
}
