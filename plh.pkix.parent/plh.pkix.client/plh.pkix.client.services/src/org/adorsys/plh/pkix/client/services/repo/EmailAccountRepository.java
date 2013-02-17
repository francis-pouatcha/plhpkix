package org.adorsys.plh.pkix.client.services.repo;

import org.adorsys.plh.pkix.client.services.datatypes.EmailAccount;

/**
 * Describes an email account storage.
 * 
 * @author francis
 *
 */
public interface EmailAccountRepository {

	public void updateEmailAcount(EmailAccount emailAccount);
	
	public EmailAccount findEmailAccount(String emailStrict);
}
