package org.adorsys.plh.pkix.core.smime.contact;

import java.util.Arrays;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;

public class AccountManager {

	private static final String CONTACTS_DIR_NAME="contacts";
//	private final FileWrapper accountDir;
	private final ContactManager contactManager;
	private final ActionContext accountContext;
	
	private final BuilderChecker checker = new BuilderChecker(AccountManager.class);
	/**
	 * Create a contact manager.
	 * 
	 * @param container
	 * @param rootDir
	 * @param userName
	 * @param email
	 * @param accountStorePass shall be kept secret.
	 * @param accountKeyPass shall be kept secret.
	 */
	public AccountManager(ActionContext accountContext, 
			FileWrapper accountDir, String userName, 
			String email, char[] accountPass){		
		
		checker.checkNull(accountContext, accountDir, userName, email, accountPass);
//		this.accountDir = accountDir;
		this.accountContext = accountContext;
		accountDir.getKeyStoreWraper().setKeyPass(accountPass);

		X500Name accountX500Name = X500NameHelper.makeX500Name(userName, email, UUID.randomUUID().toString());
		GeneralNames accountSubjectAlternativeNames = X500NameHelper.makeSubjectAlternativeName(accountX500Name, Arrays.asList(email));
		new KeyPairBuilder()
					.withEndEntityName(accountX500Name)
					.withKeyStoreWraper(accountDir.getKeyStoreWraper())
					.withSubjectAlternativeNames(accountSubjectAlternativeNames)
					.build();
		FileWrapper contactsDir = accountDir.newChild(CONTACTS_DIR_NAME);
		contactManager = new ContactManagerImpl(accountDir.getKeyStoreWraper(), contactsDir);
		accountContext.put(ContactManager.class, contactManager);
	}

	public AccountManager(ActionContext accountContext, FileWrapper accountDir){		
//		this.accountDir = accountDir;
		this.accountContext = accountContext;
		FileWrapper contactsDir = accountDir.newChild(CONTACTS_DIR_NAME);
		contactManager = new ContactManagerImpl(accountDir.getKeyStoreWraper(), contactsDir);
		accountContext.put(ContactManager.class, contactManager);
	}

	public ActionContext getAccountContext() {
		return accountContext;
	}
}
