package org.adorsys.plh.pkix.core.test.utils.jca;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyAliasUtils;
import org.adorsys.plh.pkix.core.utils.PrivateKeyUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.jca.X509CertificateBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyPairAndCertificateHolder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class KeyPairBuilderTest {
	
	static Provider provider = ProviderUtils.bcProvider;
	@SuppressWarnings("unused")
	@Test
	public void testBuild() {
		KeyStore keyStore;
		try {
			keyStore = KeyStore.Builder.newInstance(
					KeyPairBuilder.KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection("Keystore password".toCharArray()))
					.getKeyStore();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}

		X500Name endEntityName = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@adorsys.com");
		String alias = null;
		try {
			alias = new KeyPairBuilder()
				.withEndEntityName(endEntityName)
				.withKeyStore(keyStore)
				.build("key store password".toCharArray());
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}
		try {
			Key key = keyStore.getKey(alias, "key store password".toCharArray());
		} catch (UnrecoverableKeyException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.getMessage());
		}
		
		try {
			Certificate certificate = keyStore.getCertificate(alias);
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		} catch (CertificateEncodingException e) {
			Assert.fail(e.getMessage());
		} catch (IOException e) {
			Assert.fail(e.getMessage());
		}
		
		try {
			Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection("key store password".toCharArray()));
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
			PrivateKey privateKey = pkEntry.getPrivateKey();
			Certificate certificate = pkEntry.getCertificate();
			Certificate[] certificateChain = pkEntry.getCertificateChain();
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.getMessage());
		} catch (UnrecoverableEntryException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void testGenerateSelfSignedKeyPair() {
		X500Name endEntityName = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@adorsys.com");
		@SuppressWarnings("unused")
		KeyPairAndCertificateHolder alias = new KeyPairBuilderMock().generateSelfSignedKeyPair(endEntityName);
	}

	class KeyPairBuilderMock extends KeyPairBuilder {
		@Override
		protected KeyPairAndCertificateHolder generateSelfSignedKeyPair(
				X500Name x500Name) {
			return super.generateSelfSignedKeyPair(x500Name);
		}
		
	}
	
	/**
	 * Situation occurs, when the initial key is created with a self signed certificate.
	 * 
	 * Then we want to import a ca signed certificate without rmoving the initial record.
	 * 
	 * The application using this class will like to have different ca certify the same key.
	 * 
	 */
	@Test
	public void testSaveTwoPrivateKeyEntriesWithSameKey(){
		char[] francisKeystorePassword = "Keystore password".toCharArray();
		KeyStore francisKeyStore;
		try {
			francisKeyStore = KeyStore.Builder.newInstance(
					KeyPairBuilder.KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection(francisKeystorePassword))
					.getKeyStore();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}

		char[] caKeystorePassword = "Keystore password".toCharArray();
		KeyStore caKeyStore;
		try {
			caKeyStore = KeyStore.Builder.newInstance(
					KeyPairBuilder.KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection(caKeystorePassword))
					.getKeyStore();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}

		char[] scaKeystorePassword = "Second Keystore password".toCharArray();
		KeyStore scaKeyStore;
		try {
			scaKeyStore = KeyStore.Builder.newInstance(
					KeyPairBuilder.KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection(scaKeystorePassword))
					.getKeyStore();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
		
		X500Name francisEntityName = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@adorsys.com");
		char[] francisKeyPass = "francis key store password".toCharArray();
		String francisAlias = null;
		PrivateKeyEntry francisPkEntry=null;
		try {
			francisAlias = new KeyPairBuilder()
				.withEndEntityName(francisEntityName)
				.withKeyStore(francisKeyStore)
				.build(francisKeyPass);
			Entry entry = francisKeyStore.getEntry(francisAlias, new KeyStore.PasswordProtection(francisKeyPass));
			francisPkEntry = (PrivateKeyEntry) entry;
			Certificate[] francisCertificateChain = francisKeyStore.getCertificateChain(francisAlias);
			Assert.assertEquals(1, francisCertificateChain.length);
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.getMessage());
		} catch (UnrecoverableEntryException e) {
			Assert.fail(e.getMessage());
		}
		
		X500Name caEntityName = X500NameHelper.makeX500Name("Adrsys Ca", "ca@adorsys.com");
		String caAlias = null;
		char[] caKeyPass = "ca key store password".toCharArray();
		PrivateKeyEntry caPkEntry=null;
		try {
			caAlias = new KeyPairBuilder()
				.withEndEntityName(caEntityName)
				.withKeyStore(caKeyStore)
				.build(caKeyPass);
			Entry entry = caKeyStore.getEntry(caAlias, new KeyStore.PasswordProtection(caKeyPass));
			caPkEntry = (PrivateKeyEntry) entry;
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.getMessage());
		} catch (UnrecoverableEntryException e) {
			Assert.fail(e.getMessage());
		}
		
		X500Name scaEntityName = X500NameHelper.makeX500Name("Megasoft Ca", "ca@megasoft.com");
		String scaAlias = null;
		char[] scaKeyPass = "sca key store password".toCharArray();
		PrivateKeyEntry scaPkEntry=null;
		try {
			scaAlias = new KeyPairBuilder()
				.withEndEntityName(scaEntityName)
				.withKeyStore(scaKeyStore)
				.build(scaKeyPass);
			Entry entry = scaKeyStore.getEntry(scaAlias, new KeyStore.PasswordProtection(scaKeyPass));
			scaPkEntry = (PrivateKeyEntry) entry;
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.getMessage());
		} catch (UnrecoverableEntryException e) {
			Assert.fail(e.getMessage());
		}

		
		X509CertificateHolder subjectCertificate = null;
		PrivateKey issuerPrivatekey = caPkEntry.getPrivateKey();
		X509CertificateHolder issuerCertificate = null;
		try {
			subjectCertificate = new X509CertificateHolder(francisPkEntry.getCertificate().getEncoded());
			issuerCertificate = new X509CertificateHolder(caPkEntry.getCertificate().getEncoded());
		} catch (CertificateEncodingException e) {
			Assert.fail(e.getMessage());
		} catch (IOException e) {
			Assert.fail(e.getMessage());
		}

//		X509CertificateHolder francisCertificateFromCa = V3CertificateUtils.makeV3Certificate(
//				subjectCertificate , issuerPrivatekey, issuerCertificate, 
//					subjectCertificate.getNotBefore(), subjectCertificate.getNotAfter(), provider);
		X509CertificateHolder francisCertificateFromCa = 
			new X509CertificateBuilder()
				.setCa(false)
				.setIssuerCertificate(issuerCertificate)
				.setSubjectSampleCertificate(subjectCertificate)
				.build(issuerPrivatekey);
		
		String francisKeyAliasFromCa = null;
		try {
			francisKeyAliasFromCa = KeyAliasUtils.computeKeyAlias(francisCertificateFromCa);
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		}
		Certificate[] francisChainWithCa = new Certificate[]{
				V3CertificateUtils.getCertificate(francisCertificateFromCa, provider),
				V3CertificateUtils.getCertificate(issuerCertificate, provider)
		};
		char[] francisKeyPass2 = "another francis key store password".toCharArray();
		PrivateKey francisPrivateKey = francisPkEntry.getPrivateKey();
		PrivateKey clonedFrancisPrivateKey = PrivateKeyUtils.clonePrivateKey(francisPrivateKey);
		try {
			francisKeyStore.setKeyEntry(francisKeyAliasFromCa, clonedFrancisPrivateKey, francisKeyPass2, francisChainWithCa);
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}
		
		try {
			Enumeration<String> aliases = francisKeyStore.aliases();
			List<String> aliasList = new ArrayList<String>();
			while (aliases.hasMoreElements()) {
				String string = (String) aliases.nextElement();
				aliasList.add(string);
			}
			Assert.assertTrue(aliasList.contains(francisAlias));
			Assert.assertTrue(aliasList.contains(francisKeyAliasFromCa));
			
			Certificate[] certificateChain = francisKeyStore.getCertificateChain(francisAlias);
//			Assert.assertEquals(1, certificateChain.length);
			Certificate[] certificateChain2 = francisKeyStore.getCertificateChain(francisKeyAliasFromCa);
			Assert.assertEquals(2, certificateChain2.length);
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}

		PrivateKey issuerPrivatekey2 = scaPkEntry.getPrivateKey();
		X509CertificateHolder issuerCertificate2 = null;
		try {
			issuerCertificate2 = new X509CertificateHolder(scaPkEntry.getCertificate().getEncoded());
		} catch (CertificateEncodingException e) {
			Assert.fail(e.getMessage());
		} catch (IOException e) {
			Assert.fail(e.getMessage());
		}

//		X509CertificateHolder francisCertificateFromSCa = V3CertificateUtils.makeV3Certificate(subjectCertificate , 
//				issuerPrivatekey2, issuerCertificate2, 
//					subjectCertificate.getNotBefore(), subjectCertificate.getNotAfter(), provider);
		X509CertificateHolder francisCertificateFromSCa = new X509CertificateBuilder()
			.setCa(false)
			.setIssuerCertificate(issuerCertificate2)
			.setSubjectSampleCertificate(subjectCertificate)
			.build(issuerPrivatekey2);
		String francisKeyAliasFromSCa = null;
		try {
			francisKeyAliasFromSCa = KeyAliasUtils.computeKeyAlias(francisCertificateFromSCa);
		} catch (CertificateException e) {
			Assert.fail(e.getMessage());
		}
		Certificate[] francisChainWithSCa = new Certificate[]{
				V3CertificateUtils.getCertificate(francisCertificateFromSCa, provider),
				V3CertificateUtils.getCertificate(issuerCertificate2, provider)
		};
		char[] francisKeyPass3 = "third francis key store password".toCharArray();
		PrivateKey clonedFrancisPrivateKey2 = PrivateKeyUtils.clonePrivateKey(francisPrivateKey);
		try {
			francisKeyStore.setKeyEntry(francisKeyAliasFromSCa, clonedFrancisPrivateKey2, francisKeyPass3, francisChainWithSCa);
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}
		
		try {
			Enumeration<String> aliases = francisKeyStore.aliases();
			List<String> aliasList = new ArrayList<String>();
			while (aliases.hasMoreElements()) {
				String string = (String) aliases.nextElement();
				aliasList.add(string);
			}
			Assert.assertTrue(aliasList.contains(francisAlias));
			Assert.assertTrue(aliasList.contains(francisKeyAliasFromCa));
			Assert.assertTrue(aliasList.contains(francisKeyAliasFromSCa));
			
			Certificate[] certificateChain3 = francisKeyStore.getCertificateChain(francisAlias);
//			Assert.assertEquals(1, certificateChain.length);
			Certificate[] certificateChain4 = francisKeyStore.getCertificateChain(francisKeyAliasFromSCa);
			Assert.assertEquals(2, certificateChain4.length);
			Certificate[] certificateChain2 = francisKeyStore.getCertificateChain(francisKeyAliasFromCa);
			Assert.assertEquals(2, certificateChain2.length);
		} catch (KeyStoreException e) {
			Assert.fail(e.getMessage());
		}
	
	
	
	}
}
