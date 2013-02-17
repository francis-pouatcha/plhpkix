package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSEncryptor;
import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.jca.PasswordCallbackHandler;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class CMSEncryptorTest {
	private Provider provider = ProviderUtils.bcProvider;
	private X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz");

	@Test
	public void test() throws Exception {

		char[] keystorePass = "Keystore password".toCharArray();
		char[] privatekeyPass = "private key password".toCharArray();
		KeyStore keyStore;
		try {
			keyStore = KeyStore.Builder.newInstance(
					KeyPairBuilder.KEYSTORETYPE_STRING,
					ProviderUtils.bcProvider, 
					new KeyStore.PasswordProtection(keystorePass))
					.getKeyStore();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
		
		String keyAlias = new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withKeyStore(keyStore)
				.build(privatekeyPass);
		
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(keystorePass));
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getCertificate(subjectCertificate, provider);

		File inputFile = new File("test/resources/rfc4210.pdf");

		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart encryptedPartOut = new CMSEncryptor()
			.withInputPart(inputPart)
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.encrypt();
		inputPart.dispose();
		
		File encryptedFile = new File("target/rfc4210.pdf.testEncryptDecrypt.encrypted");
		encryptedPartOut.writeTo(encryptedFile);
		encryptedPartOut.dispose();
		
		// make sure the encrypted content stream is different.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, encryptedFile));

		CMSPart encryptedPartIn = CMSPart.instanceFrom(encryptedFile);
		CMSPart decryptedPart = new CMSDecryptor()
			.withCallbackHandler(new PasswordCallbackHandler(privatekeyPass))
			.withInputPart(encryptedPartIn)
			.withKeyStore(keyStore)
			.decrypt();
		encryptedPartIn.dispose();
		
		File decryptedFile = new File("target/rfc4210.pdf.testEncryptDecrypt.decrypted");
		decryptedPart.writeTo(decryptedFile);
		decryptedPart.dispose();
		Assert.assertTrue(FileUtils.contentEquals(
				inputFile, decryptedFile));
		
		FileCleanup.deleteQuietly(encryptedFile,decryptedFile);
	}

}
