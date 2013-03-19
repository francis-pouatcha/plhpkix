package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSSignerEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedSignerEncryptor;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class CMSStreamedSignerEncryptorTest2 {
	private X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz", UUID.randomUUID().toString());

	@Test
	public void test() throws Exception {
		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(null, "private key password".toCharArray(), "Keystore password".toCharArray());
		new KeyPairBuilder()
			.withEndEntityName(subjectX500Name)
			.withKeyStoreWraper(keyStoreWraper)
			.build();
		ContactManager contactManager = new ContactManagerImpl(keyStoreWraper, null);
		PrivateKeyEntry privateKeyEntry = contactManager.getMainMessagePrivateKeyEntry();
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(subjectCertificate);
		
		File inputFile = new File("test/resources/rfc4210.pdf");
		File signedEncryptedFile = new File("target/rfc4210.pdf.CMSStreamedSignerEncryptorTest21.signed.encrypted");
		FileOutputStream signedEncryptedOutputStream = new FileOutputStream(signedEncryptedFile);
		OutputStream signingEncryptingOutputStream = new CMSStreamedSignerEncryptor()
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.withOutputStream(signedEncryptedOutputStream)
			.signingEncryptingOutputStream(privateKeyEntry);
		
		FileInputStream inputFileInputStream = new FileInputStream(inputFile);
		IOUtils.copy(inputFileInputStream, signingEncryptingOutputStream);
		IOUtils.closeQuietly(inputFileInputStream);
		IOUtils.closeQuietly(signingEncryptingOutputStream);		
		
		// make sure the signed and encrypted content stream is different from original.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, signedEncryptedFile));

		
		File signedEncryptedFile3 = new File("target/rfc4210.pdf.CMSStreamedSignerEncryptorTest23.signed.encrypted");
		FileOutputStream signedEncryptedOutputStream3 = new FileOutputStream(signedEncryptedFile3);
		OutputStream signingEncryptingOutputStream3 = new CMSStreamedSignerEncryptor()
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.withOutputStream(signedEncryptedOutputStream3)
			.signingEncryptingOutputStream(privateKeyEntry);
		
		FileInputStream inputFileInputStream3 = new FileInputStream(inputFile);
		IOUtils.copy(inputFileInputStream3, signingEncryptingOutputStream3);
		IOUtils.closeQuietly(inputFileInputStream3);
		IOUtils.closeQuietly(signingEncryptingOutputStream3);		
		
		// make sure two signed and encrypted content stream are different event if
		// with same input
		Assert.assertFalse(FileUtils.contentEquals(signedEncryptedFile, signedEncryptedFile3));
		
		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart signedEncryptedPartOut = new CMSSignerEncryptor()
			.withInputPart(inputPart)
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.signEncrypt(privateKeyEntry);
		inputPart.dispose();

		File signedEncryptedFile2 = new File("target/rfc4210.pdf.CMSStreamedSignerEncryptorTest22.signed.encrypted");
		signedEncryptedPartOut.writeTo(signedEncryptedFile2);
		signedEncryptedPartOut.dispose();

		Assert.assertFalse(FileUtils.contentEquals(signedEncryptedFile, signedEncryptedFile2));
		
		FileCleanup.deleteQuietly(signedEncryptedFile, signedEncryptedFile2, signedEncryptedFile3);
	}

}
