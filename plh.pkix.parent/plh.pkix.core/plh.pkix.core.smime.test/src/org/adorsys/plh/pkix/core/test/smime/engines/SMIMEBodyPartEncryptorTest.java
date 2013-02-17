package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartEncryptor;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.jca.PasswordCallbackHandler;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class SMIMEBodyPartEncryptorTest {
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
        MimeBodyPart document = new MimeBodyPart();
        document.attachFile(inputFile);

        File encryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartEncryptorTest.test.encrypted");

		List<X509Certificate> recipientX509Certificates = Arrays.asList(x509Certificate);
		MimeBodyPart encryptedBodyPart = new SMIMEBodyPartEncryptor()
			.withMimeBodyPart(document)
			.withRecipientX509Certificates(recipientX509Certificates)
			.encrypt();
		
		FileOutputStream encryptOutputStream = new FileOutputStream(encryptedOutputFile);
		encryptedBodyPart.writeTo(encryptOutputStream);
		IOUtils.closeQuietly(encryptOutputStream);

		// make sure the encrypted content stream is different.
		Assert.assertFalse(FileUtils.contentEquals(
				inputFile, encryptedOutputFile));
		
		FileInputStream encryptedBodyPartInputStream = new FileInputStream(encryptedOutputFile);
		MimeBodyPart encryptedBodyPart2 = new MimeBodyPart(encryptedBodyPartInputStream);
		MimeBodyPart decryptedBodyPart2 = new SMIMEBodyPartDecryptor()
			.withCallbackHandler(new PasswordCallbackHandler(privatekeyPass))
			.withKeyStore(keyStore)
			.withMimeBodyPart(encryptedBodyPart2)
			.decrypt();

		IOUtils.closeQuietly(encryptedBodyPartInputStream);
		
		File decryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartEncryptorTest.test.derypted.pdf");
		decryptedBodyPart2.saveFile(decryptedOutputFile);

		Assert.assertTrue(FileUtils.contentEquals(inputFile,decryptedOutputFile));
		
	}

}
