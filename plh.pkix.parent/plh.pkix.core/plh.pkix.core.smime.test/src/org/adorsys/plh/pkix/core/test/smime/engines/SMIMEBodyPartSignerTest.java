package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartSigner;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartVerifier;
import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;

public class SMIMEBodyPartSignerTest {

	static X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz");
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


		ArrayList<X509Certificate> senderCertificateChain = new ArrayList<X509Certificate>();
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add((X509Certificate) certificate);
		}
		
		
        MimeBodyPart document = new MimeBodyPart();
        File inputFIle = new File("test/resources/rfc4210.pdf");
        document.attachFile(inputFIle);
        
		MimeBodyPart signedBodyPart = new SMIMEBodyPartSigner()
			.withIssuerName(subjectX500Name)
			.withMimeBodyPart(document)
			.withSenderCertificateChain(senderCertificateChain)
			.sign(privateKeyEntry.getPrivateKey());
		
		File singnedFile = new File("target/rfc4210.pdf.SMIMEBodyPartSignerTest.test.signed.pk7");
		FileOutputStream fileOutputStream = new FileOutputStream(singnedFile);
		signedBodyPart.writeTo(fileOutputStream);
		IOUtils.closeQuietly(fileOutputStream);
		
		Assert.assertFalse(FileUtils.contentEquals(inputFIle, singnedFile));

        MimeBodyPart readSignedBodyPart = signedBodyPart;
		
        CMSSignedMessageValidator<MimeBodyPart> signedMessageValidator = new SMIMEBodyPartVerifier()
			.withKeyStore(keyStore)
			.withSignedBodyPart(readSignedBodyPart)
			.readAndVerify();

        MimeBodyPart content = signedMessageValidator.getContent();
		String verifiedOut = "target/rfc4210.pdf.SMIMEBodyPartSignerTest.test.verified.pdf";
		FileOutputStream verifiedOutputStream = new FileOutputStream(verifiedOut);
        InputStream inputStream = null;
        try {
	      	inputStream = content.getInputStream();
	      	IOUtils.copy(inputStream, verifiedOutputStream);
		} finally {
			IOUtils.closeQuietly(inputStream);
			IOUtils.closeQuietly(verifiedOutputStream);
		}
        
		boolean contentEquals = FileUtils.contentEquals(
			new File("test/resources/rfc4210.pdf"), 
			new File(verifiedOut));
		Assert.assertTrue(contentEquals);
		
		FileUtils.deleteQuietly(singnedFile);
		FileUtils.deleteQuietly(new File(verifiedOut));
	}

	@Test
	public void testOI() throws Exception {
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
			.withSenderCertificateChain(senderCertificateChain)
			.sign(privateKeyEntry.getPrivateKey());
		signedBodyPart.setHeader("Content-Transfer-Encoding", "binary");
		File signedFile = new File("target/rfc4210.pdf.SMIMEBodyPartSignerTest.testOI.signed.pk7");
		OutputStream fileOutputStream = new BufferedOutputStream(new FileOutputStream(signedFile));
		signedBodyPart.writeTo(fileOutputStream);
		IOUtils.closeQuietly(fileOutputStream);
		
		BufferedInputStream singnedFileInputStream = new BufferedInputStream(new FileInputStream(signedFile));
        MimeBodyPart readSignedBodyPart = new MimeBodyPart(singnedFileInputStream);
		
        CMSSignedMessageValidator<MimeBodyPart> signedMessageValidator = new SMIMEBodyPartVerifier()
			.withKeyStore(keyStore)
			.withSignedBodyPart(readSignedBodyPart)
			.readAndVerify();

        MimeBodyPart content = signedMessageValidator.getContent();
		File verifiedOut = new File("target/rfc4210.pdf.SMIMEBodyPartSignerTest.testOI.verified.pdf");
		FileOutputStream verifiedOutputStream = new FileOutputStream(verifiedOut);
        InputStream inputStream = null;
        try {
	      	inputStream = content.getInputStream();
	      	IOUtils.copy(inputStream, verifiedOutputStream);
		} finally {
			IOUtils.closeQuietly(inputStream);
			IOUtils.closeQuietly(verifiedOutputStream);
			IOUtils.closeQuietly(singnedFileInputStream);
		}
        
        Assert.assertTrue(FileUtils.contentEquals(inputFile, verifiedOut));
		
		FileUtils.deleteQuietly(signedFile);
		FileUtils.deleteQuietly(verifiedOut);
	}

}
