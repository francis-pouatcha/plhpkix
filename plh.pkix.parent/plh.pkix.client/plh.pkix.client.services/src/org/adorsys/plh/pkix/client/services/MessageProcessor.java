package org.adorsys.plh.pkix.client.services;

public interface MessageProcessor {
	
	public void reciever(String senderEmail, String subject, String message, byte[] payload);

}
