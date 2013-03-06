package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartDecryptorVerifier;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartSigner;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartSignerEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartVerifier;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class SMIMEBodyPartSignerEncryptorTest {
	private X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz", UUID.randomUUID().toString());

	@Test
	public void test() throws Exception {
		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(null, "private key password".toCharArray(), "Keystore password".toCharArray());
		X509CertificateHolder messagingCertificate = new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withKeyStoreWraper(keyStoreWraper)
				.build();
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findPrivateKeyEntry(messagingCertificate);
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(subjectCertificate);

		ArrayList<X509Certificate> senderCertificateChain = new ArrayList<X509Certificate>();
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add((X509Certificate) certificate);
		}
		
		File inputFile = new File("test/resources/rfc4210.pdf");
        MimeBodyPart document = new MimeBodyPart();
        document.attachFile(inputFile);
        document.setHeader("Content-Type", "application/octet-stream");
        document.setHeader("Content-Transfer-Encoding", "binary");
        
        List<X509Certificate> recipientX509Certificates = Arrays.asList(x509Certificate);
		MimeBodyPart signEncryptedBodyPartOut = new SMIMEBodyPartSignerEncryptor()
        	.withIssuerName(subjectX500Name)
        	.withRecipientX509Certificates(recipientX509Certificates)
        	.withMimeBodyPart(document)
        	.signEncrypt(privateKeyEntry);

        File signedEncryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.test.signed.encrypted");
        
        FileOutputStream signedEncryptedOutputStream = new FileOutputStream(signedEncryptedOutputFile);
        signEncryptedBodyPartOut.writeTo(signedEncryptedOutputStream);
        IOUtils.closeQuietly(signedEncryptedOutputStream);

        Assert.assertFalse(FileUtils.contentEquals(
			inputFile, 
			signedEncryptedOutputFile));
        
        FileInputStream signedEncryptedInputStream = new FileInputStream(signedEncryptedOutputFile);
        MimeBodyPart signEncryptedBodyPartIn = new MimeBodyPart(signedEncryptedInputStream);
		CMSSignedMessageValidator<MimeBodyPart> signedMessageValidator = new SMIMEBodyPartDecryptorVerifier()
		.withKeyStoreWraper(keyStoreWraper)
		.withMimeBodyPart(signEncryptedBodyPartIn)
		.decryptAndVerify();
        
        MimeBodyPart content = signedMessageValidator.getContent();
		File verifiedOut = new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.test.decrypted.verified.pdf");
		FileOutputStream verifiedOutputStream = new FileOutputStream(verifiedOut);
        InputStream inputStream = null;
        try {
	      	inputStream = content.getInputStream();
	      	IOUtils.copy(inputStream, verifiedOutputStream);
		} finally {
			IOUtils.closeQuietly(inputStream);
			IOUtils.closeQuietly(verifiedOutputStream);
		}
        
        Assert.assertTrue(FileUtils.contentEquals(
			inputFile, 
			verifiedOut));
		
		FileUtils.deleteQuietly(signedEncryptedOutputFile);
		FileUtils.deleteQuietly(verifiedOut);
	}

	@Test
	public void testSteps() throws Exception {
		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(null, "private key password".toCharArray(), "Keystore password".toCharArray());
		X509CertificateHolder messagingCertificate = new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withKeyStoreWraper(keyStoreWraper)
				.build();
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findPrivateKeyEntry(messagingCertificate);

		ArrayList<X509Certificate> senderCertificateChain = new ArrayList<X509Certificate>();
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add((X509Certificate) certificate);
		}
		
        MimeBodyPart document = new MimeBodyPart();
		File inputFile = new File("test/resources/rfc4210.pdf");
        document.attachFile(inputFile);
        document.setHeader("Content-Type", "application/octet-stream");
        document.setHeader("Content-Transfer-Encoding", "binary");
        
		MimeBodyPart signedBodyPart = new SMIMEBodyPartSigner()
			.withIssuerName(subjectX500Name)
			.withMimeBodyPart(document)
			.sign(privateKeyEntry);
		signedBodyPart.setHeader("Content-Transfer-Encoding", "binary");
		
		File singnedFile = new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.testSteps.signed.pk7");
		FileOutputStream fileOutputStream = new FileOutputStream(singnedFile);
		signedBodyPart.writeTo(fileOutputStream);
		IOUtils.closeQuietly(fileOutputStream);
		
		Assert.assertFalse(FileUtils.contentEquals(inputFile, singnedFile));
				
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(subjectCertificate);
		
        File encryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.testSteps.encrypted");
        FileInputStream singnedFileInputStream = new FileInputStream(singnedFile);
        MimeBodyPart signedBodyPart2 = new MimeBodyPart(singnedFileInputStream);
		List<X509Certificate> recipientX509Certificates = Arrays.asList(x509Certificate);
		MimeBodyPart encryptedBodyPart = new SMIMEBodyPartEncryptor()
			.withMimeBodyPart(signedBodyPart2)
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
			.withKeyStoreWraper(keyStoreWraper)
			.withMimeBodyPart(encryptedBodyPart2)
			.decrypt();

		IOUtils.closeQuietly(encryptedBodyPartInputStream);
		
		File decryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.testSteps.derypted.pdf");
		FileOutputStream decryptedFileOutputStream = new FileOutputStream(decryptedOutputFile);
		decryptedBodyPart2.writeTo(decryptedFileOutputStream);
		IOUtils.closeQuietly(decryptedFileOutputStream);

		Assert.assertTrue(FileUtils.contentEquals(singnedFile,decryptedOutputFile));

		FileInputStream decryptedInputStream = new FileInputStream(decryptedOutputFile);
        MimeBodyPart readSignedBodyPart = new MimeBodyPart(decryptedInputStream);
		
        CMSSignedMessageValidator<MimeBodyPart> signedMessageValidator = new SMIMEBodyPartVerifier()
			.withKeyStoreWraper(keyStoreWraper)
			.withSignedBodyPart(readSignedBodyPart)
			.readAndVerify();

        MimeBodyPart content = signedMessageValidator.getContent();
		File verifiedOut = new File("target/rfc4210.pdf.SMIMEBodyPartSignerEncryptorTest.testSteps.verified.pdf");
		FileOutputStream verifiedOutputStream = new FileOutputStream(verifiedOut);
        InputStream inputStream = null;
        try {
	      	inputStream = content.getInputStream();
	      	IOUtils.copy(inputStream, verifiedOutputStream);
		} finally {
			IOUtils.closeQuietly(inputStream);
			IOUtils.closeQuietly(verifiedOutputStream);
		}
        
        Assert.assertTrue(FileUtils.contentEquals(inputFile, verifiedOut));
		
		FileUtils.deleteQuietly(singnedFile);
		FileUtils.deleteQuietly(verifiedOut);
		FileUtils.deleteQuietly(decryptedOutputFile);
		FileUtils.deleteQuietly(encryptedOutputFile);
		
	}
}
