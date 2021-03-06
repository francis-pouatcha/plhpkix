package org.adorsys.plh.pkix.server.cmp.messaging;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;


@Entity
@NamedQueries({
	@NamedQuery(name=CMPReplyData.BY_RECIPIENT_SORTED_BY_RECEPTIONTIME, 
			query="SELECT d FROM CMPReplyData d WHERE d.recipient=:recipient ORDER BY d.receptionTime"),
	@NamedQuery(name=CMPReplyData.BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
			query="SELECT d FROM CMPReplyData d WHERE d.recipient=:recipient and d.transactionID=:transactionID ORDER BY d.receptionTime"),
	@NamedQuery(name=CMPReplyData.BY_SENDER_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
			query="SELECT d FROM CMPReplyData d WHERE d.sender=:sender and d.transactionID=:transactionID ORDER BY d.receptionTime")
})
@Inheritance(strategy=InheritanceType.TABLE_PER_CLASS)
public class CMPReplyData extends AbstractCMPMessageData {
	
	public static final String BY_RECIPIENT_SORTED_BY_RECEPTIONTIME="CMPREPLYDATA_BY_RECIPIENT_SORTED_BY_RECEPTIONTIME";
	public static final String BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME="CMPREPLYDATA_BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME";
	public static final String BY_SENDER_TRANSACTIONID_SORTED_BY_RECEPTIONTIME="CMPREPLYDATA_BY_SENDER_TRANSACTIONID_SORTED_BY_RECEPTIONTIME";
	
	@Id
	private String id;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
}
