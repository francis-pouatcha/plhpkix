package org.adorsys.plh.pkix.server.cmp.endentity;

import java.util.List;
import java.util.UUID;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

@Stateless
public class EndEntityKeyRepository {

	@PersistenceContext
	private EntityManager entityManager;
	
	public List<EndEntityKey> findEndEntityKeyBySubjectName(String subjectName){
		TypedQuery<EndEntityKey> query = entityManager.createNamedQuery(EndEntityKey.BY_SUBJECT_NAME, EndEntityKey.class);
		query.setParameter("subjectName", subjectName);
		return query.getResultList();
	}

	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public EndEntityKey storeEndEntityKey(EndEntityKey endEntityKey) {
		endEntityKey.setId(UUID.randomUUID().toString());
		entityManager.persist(endEntityKey);
		return endEntityKey;
	}

}
