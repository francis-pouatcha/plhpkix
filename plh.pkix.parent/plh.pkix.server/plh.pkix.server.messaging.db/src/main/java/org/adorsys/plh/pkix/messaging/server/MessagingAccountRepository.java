package org.adorsys.plh.pkix.messaging.server;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@Stateless
public class MessagingAccountRepository {

	@PersistenceContext
	private EntityManager entityManager;
	
	public void newMessagingAccount(MessagingAccount messagingAccount){
		entityManager.persist(messagingAccount);
	}
	
	public MessagingAccount findByEmail(String email){
		return entityManager.createNamedQuery(MessagingAccount.BY_EMAIL, MessagingAccount.class)
			.setParameter("email", email)
			.setMaxResults(1)
			.getSingleResult();
	}
}
