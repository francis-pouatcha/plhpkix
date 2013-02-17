package org.adorsys.plh.pkix.client.services;

import java.util.List;

import javax.activation.DataSource;

/**
 * The messaging service is used to exchange message among plooh clients.
 * 
 * We can use many schemes and protocols to implement the messaging.
 * 
 * A user can specify it's preferred messaging scheme in the certificate it uses 
 * to communicate with other users.
 * 
 * The unique identifier is the user is his strict email address. Like fpo@adorsys.com,
 * not "Francis Pouatcha"<fpo@adorsys.com>. 
 * 
 * We also assume throughout this framework that the strict email address is the 
 * X500 Common Name of the user.
 * 
 * @author francis
 *
 */
public interface MessagingService {

	/**
	 * Send a message to the receiver.
	 * 
	 * @param recieverEmail
	 * @param subject
	 * @param message
	 * @param attchements
	 */
	public void send(String recieverEmail, String subject, 
			String plainText,String htmlText, List<DataSource> attchements);
	
	/**
	 * Trigger processing of a message sent to the owner of this message service.
	 * 
	 * @param messageProcessor
	 */
	public void registerProcessor(MessageProcessor messageProcessor);
	
}
