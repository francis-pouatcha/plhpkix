package org.adorys.plh.pkix.server.cmp.messaging;

import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;

@Stateless
public class CMPReplyDataRepository {

	@PersistenceContext
	private EntityManager entityManager;
	
	public CMPReplyData findByTransactionIdAndRecipient(ASN1OctetString transactionID, X500Name recipient){
		TypedQuery<CMPReplyData> query = entityManager.createNamedQuery(
				CMPReplyData.BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
				CMPReplyData.class);
		query.setParameter("recipient", X500NameHelper.getCN(recipient));
		query.setParameter("transactionID", transactionID.toString());
		query.setMaxResults(1);
		List<CMPReplyData> resultList = query.getResultList();
		if(resultList.isEmpty()) return null;
		return resultList.iterator().next();
	}
	
	public CMPReplyData findByTransactionIdAndSender(ASN1OctetString transactionID, X500Name sender){
		TypedQuery<CMPReplyData> query = entityManager.createNamedQuery(
				CMPReplyData.BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
				CMPReplyData.class);
		query.setParameter("sender", X500NameHelper.getCN(sender));
		query.setParameter("transactionID", transactionID.toString());
		query.setMaxResults(1);
		List<CMPReplyData> resultList = query.getResultList();
		if(resultList.isEmpty()) return null;
		return resultList.iterator().next();
	}
	
	public void create(CMPReplyData requestData){
		entityManager.persist(requestData);
	}
	
	public void remove(String id){
		CMPReplyData requestData = entityManager.find(CMPReplyData.class, id);
		entityManager.remove(requestData);
	}

	public void remove(CMPReplyData replyData){
		entityManager.remove(replyData);
	}
}
