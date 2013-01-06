package org.adorys.plh.pkix.server.cmp.messaging;

import java.util.Date;

import javax.persistence.Lob;
import javax.persistence.MappedSuperclass;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

@MappedSuperclass
public abstract class AbstractCMPMessageData {
		
	/*
	 * recipient
	 * GeneralName,
	 * -- identifies the intended recipient
	 */
	@NotNull
	private String recipient;

	@NotNull
	private String sender;
	
	/*
	 * messageTime
	 * [0] GeneralizedTime
	 * OPTIONAL,
	 * -- time of production of this message (used when sender
	 * -- believes that the transport will be "suitable"; i.e.,
	 * -- that the time will still be meaningful upon receipt)
	 */
	@NotNull
	@Temporal(TemporalType.TIMESTAMP)
	private Date messageTime;

	/*
	 * transactionID [4] OCTET STRING OPTIONAL,
	 * -- identifies the transaction; i.e., this will be the same in
	 * -- corresponding request, response and confirmation messages
	 */
	@NotNull
	private String transactionID;

	@NotNull
	@Lob
	private byte[] pkiMessage;
	
	@NotNull
	@Temporal(TemporalType.TIMESTAMP)
	private Date receptionTime;

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

	public String getTransactionID() {
		return transactionID;
	}

	public void setTransactionID(String transactionID) {
		this.transactionID = transactionID;
	}

	public byte[] getPkiMessage() {
		return pkiMessage;
	}

	public void setPkiMessage(byte[] pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public Date getReceptionTime() {
		return receptionTime;
	}

	public void setReceptionTime(Date receptionTime) {
		this.receptionTime = receptionTime;
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
}
