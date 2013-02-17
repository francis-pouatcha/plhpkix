package org.adorsys.plh.pkix.messaging.server;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;

@Entity
@NamedQueries({
	@NamedQuery(name=MessageData.BY_RECIPIENT_UNDELIVERED_SORTED_BY_MESSAGETIME, 
			query="SELECT d FROM MessageData d WHERE d.recipient=:recipient and d.deliveryTime is null ORDER BY d.messageTime"),
	@NamedQuery(name=MessageData.BY_RECIPIENT_DELIVERED_SORTED_BY_MESSAGETIME, 
			query="SELECT d FROM MessageData d WHERE d.recipient=:recipient and d.deliveryTime is null ORDER BY d.messageTime"),
	@NamedQuery(name=MessageData.BY_SENDER_UNDELIVERED_SORTED_BY_MESSAGETIME, 
			query="SELECT d FROM MessageData d WHERE d.sender=:sender and d.deliveryTime is null ORDER BY d.messageTime")
})
@Inheritance(strategy=InheritanceType.TABLE_PER_CLASS)
public class MessageData extends AbstractMessageData {

	public static final String BY_RECIPIENT_UNDELIVERED_SORTED_BY_MESSAGETIME="MESSAGEDATA_BY_RECIPIENT_UNDELIVERED_SORTED_BY_MESSAGETIME";
	public static final String BY_RECIPIENT_DELIVERED_SORTED_BY_MESSAGETIME="MESSAGEDATA_BY_RECIPIENT_DELIVERED_SORTED_BY_MESSAGETIME";
	public static final String BY_SENDER_UNDELIVERED_SORTED_BY_MESSAGETIME="MESSAGEDATA_BY_SENDER_UNDELIVERED_SORTED_BY_MESSAGETIME";
	
	@Id
	private String id;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
}
