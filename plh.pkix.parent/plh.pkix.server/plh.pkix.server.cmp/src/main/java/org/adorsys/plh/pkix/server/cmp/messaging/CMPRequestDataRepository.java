package org.adorsys.plh.pkix.server.cmp.messaging;

import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;

@Stateless
public class CMPRequestDataRepository {

	@PersistenceContext
	private EntityManager entityManager;
	
	public CMPRequestData findByTransactionIdAndRecipient(ASN1OctetString transactionID, X500Name recipient){
		TypedQuery<CMPRequestData> query = entityManager.createNamedQuery(
				CMPRequestData.BY_RECIPIENT_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
				CMPRequestData.class);
		query.setParameter("recipient", X500NameHelper.getCN(recipient));
		query.setParameter("transactionID", transactionID.toString());
		query.setMaxResults(1);
		List<CMPRequestData> resultList = query.getResultList();
		if(resultList.isEmpty()) return null;
		return resultList.iterator().next();
	}

	public CMPRequestData findByTransactionIdAndSender(ASN1OctetString transactionID, X500Name sender){
		TypedQuery<CMPRequestData> query = entityManager.createNamedQuery(
				CMPRequestData.BY_SENDER_TRANSACTIONID_SORTED_BY_RECEPTIONTIME, 
				CMPRequestData.class);
		query.setParameter("sender", X500NameHelper.getCN(sender));
		query.setParameter("transactionID", transactionID.toString());
		query.setMaxResults(1);
		List<CMPRequestData> resultList = query.getResultList();
		if(resultList.isEmpty()) return null;
		return resultList.iterator().next();
	}
	
	public CMPRequestData findByRecipient(X500Name recipient){
		TypedQuery<CMPRequestData> query = entityManager.createNamedQuery(
				CMPRequestData.BY_RECIPIENT_SORTED_BY_RECEPTIONTIME, 
				CMPRequestData.class);
		query.setParameter("recipient", X500NameHelper.getCN(recipient));
		query.setMaxResults(1);
		List<CMPRequestData> resultList = query.getResultList();
		if(resultList.isEmpty()) return null;
		return resultList.iterator().next();
	}
	
	public void create(CMPRequestData requestData){
		entityManager.persist(requestData);
	}
	
	public void remove(String id){
		CMPRequestData requestData = entityManager.find(CMPRequestData.class, id);
		entityManager.remove(requestData);
	}

	public void remove(CMPRequestData requestData){
		entityManager.remove(requestData);
	}

	public CMPRequestData merge(CMPRequestData requestData){
		return entityManager.merge(requestData);
	}
}
