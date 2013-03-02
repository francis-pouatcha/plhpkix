package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class CMSEncryptorTest {
	private X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz");

	@Test
	public void test() throws Exception {

		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(null, "private key password".toCharArray(), "Keystore password".toCharArray());
		String keyAlias = new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withKeyStoreWraper(keyStoreWraper)
				.build();
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findPrivateKeyEntry(new KeyStoreAlias(keyAlias));
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(subjectCertificate);

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
			.withInputPart(encryptedPartIn)
			.withKeyStoreWraper(keyStoreWraper)
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
