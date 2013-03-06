package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.Set;

import junit.framework.Assert;

import org.adorsys.plh.pkix.core.smime.contact.AccountManager;
import org.adorsys.plh.pkix.core.smime.store.FileContainerImpl;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileContainer;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Test;

public class ContactIndexTest {
	private static final File testDir = new File("target/ContactIndexTest");
	
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
	
	@Test
	public void test() throws CertificateException, KeyStoreException, PlhCheckedException {

		// 1. Generate key pair
		AccountManager francisContactManager = createContactManager("francis", "Francis Pouatcha", "fpo@biz.com", "Francis Pouatcha Container Key Pass".toCharArray(), "Francis Pouatcha Container Store Pass".toCharArray());
		AccountManager nadegeContactManager = createContactManager("nadege", "Nadege Pouatcha", "npa@biz.com", "Nadege Pouatcha Container Key Pass".toCharArray(), "Nadege Pouatcha Container Store Pass".toCharArray());
		AccountManager sandroContactManager = createContactManager("sandro", "Sandro Sonntag", "sso@biz.com", "Sandro Sonntag Container Key Pass".toCharArray(), "Sandro Sonntag Container Store Pass".toCharArray());
		
		PrivateKeyEntry nadegePrivateKeyEntry = nadegeContactManager.getAccountKeyStoreWraper().findAnyMessagePrivateKeyEntry();
		PrivateKeyEntry sandroPrivateKeyEntry = sandroContactManager.getAccountKeyStoreWraper().findAnyMessagePrivateKeyEntry();
		francisContactManager.getContactManager().addContact(V3CertificateUtils.getX509CertificateHolder(nadegePrivateKeyEntry.getCertificate()));
		francisContactManager.getContactManager().addContact(V3CertificateUtils.getX509CertificateHolder(sandroPrivateKeyEntry.getCertificate()));

		francisContactManager = createContactManager("francis", "Francis Pouatcha", "fpo@biz.com", "Francis Pouatcha Container Key Pass".toCharArray(), "Francis Pouatcha Container Store Pass".toCharArray());
		Set<String> francisContacts = francisContactManager.getContactManager().getContactIndex().listContacts();
		Assert.assertTrue(francisContacts.contains("npa@biz.com"));
		Assert.assertTrue(francisContacts.contains("sso@biz.com"));
	}
	
	private AccountManager createContactManager(String dirName, String userName, String  email, char[] containerKeyPass, char[] containerStorePass){
		File rootDir = new File(testDir, dirName);
		FilesContainer keyStoreContainer = new UnprotectedFileContainer(rootDir);
		KeyStoreWraper containerKeyStoreWraper = new KeyStoreWraper(keyStoreContainer
				.newFile("containerKeyStore"), containerKeyPass, containerStorePass);

		PrivateKeyEntry containerMessagePrivateKeyEntry = containerKeyStoreWraper.findAnyMessagePrivateKeyEntry();
		if(containerMessagePrivateKeyEntry==null){
			new KeyPairBuilder()
				.withEndEntityName(new X500Name("cn="+userName+" container"))
				.withKeyStoreWraper(containerKeyStoreWraper)
				.build();
			containerMessagePrivateKeyEntry = containerKeyStoreWraper.findAnyMessagePrivateKeyEntry();
		}
		FilesContainer container = new FileContainerImpl(containerMessagePrivateKeyEntry, rootDir);
		FileWrapper accountDir = container.newFile("account");
		X509CertificateHolder containerCertHolder = V3CertificateUtils.getX509CertificateHolder(containerMessagePrivateKeyEntry.getCertificate());
		String keyIdentifierAsString = KeyIdUtils.createPublicKeyIdentifierAsString(containerCertHolder);
		return new AccountManager(new ActionContext(), accountDir, userName, email, keyIdentifierAsString.toCharArray());
	}
}
