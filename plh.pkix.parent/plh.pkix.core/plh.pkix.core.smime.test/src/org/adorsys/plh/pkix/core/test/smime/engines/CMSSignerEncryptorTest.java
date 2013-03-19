package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.smime.engines.CMSDecryptorVerifier;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSSignerEncryptor;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class CMSSignerEncryptorTest {
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
		
		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart signedEncryptedPartOut = new CMSSignerEncryptor()
			.withInputPart(inputPart)
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.signEncrypt(privateKeyEntry);
		inputPart.dispose();

		File signedEncryptedFile = new File("target/rfc4210.pdf.CMSSignerEncryptorTest.signed.encrypted");
		signedEncryptedPartOut.writeTo(signedEncryptedFile);
		signedEncryptedPartOut.dispose();
		
		
		// make sure the signed and encrypted content stream is different from original.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, signedEncryptedFile));

		CMSPart signedEncryptedPartIn = CMSPart.instanceFrom(signedEncryptedFile);

		CMSSignedMessageValidator<CMSPart> validator = new CMSDecryptorVerifier()
			.withInputPart(signedEncryptedPartIn)
			.withContactManager(contactManager)
			.decryptVerify();
		signedEncryptedPartIn.dispose();
		
		CMSPart decryptedVerifiedPart = validator.getContent();
		
		File decryptedVerifiedFile = new File("target/rfc4210.pdf.CMSSignerEncryptorTest.decrypted.verified");
		decryptedVerifiedPart.writeTo(decryptedVerifiedFile);
		decryptedVerifiedPart.dispose();

		// make sure decrypted and verified file is equal to original.
		Assert.assertTrue(FileUtils.contentEquals(inputFile, decryptedVerifiedFile));
		
		FileCleanup.deleteQuietly(signedEncryptedFile, decryptedVerifiedFile);
	}

}
