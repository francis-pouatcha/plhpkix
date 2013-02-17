package org.adorsys.plh.pkix.messaging.server;

import java.util.Date;

import javax.persistence.Lob;
import javax.persistence.MappedSuperclass;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

@MappedSuperclass
public abstract class AbstractMessageData {
		
	@NotNull
	private String recipient;

	@NotNull
	private String sender;
	
	@NotNull
	@Temporal(TemporalType.TIMESTAMP)
	private Date messageTime;

	@NotNull
	@Lob
	private byte[] data;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date deliveryTime;

	public String getRecipient() {
		return recipient;
	}

	public void setRecipient(String recipient) {
		this.recipient = recipient;
	}

	public Date getMessageTime() {
		return messageTime;
	}

	public void setMessageTime(Date messageTime) {
		this.messageTime = messageTime;
	}

	public Date getDeliveryTime() {
		return deliveryTime;
	}

	public void setDeliveryTime(Date deliveryTime) {
		this.deliveryTime = deliveryTime;
	}

	public String getSender() {
		return sender;
	}

	public void setSender(String sender) {
		this.sender = sender;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

}
