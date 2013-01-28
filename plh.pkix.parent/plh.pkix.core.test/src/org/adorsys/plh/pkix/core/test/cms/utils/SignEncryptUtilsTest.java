package org.adorsys.plh.pkix.core.test.cms.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;

import org.adorsys.plh.pkix.core.cms.utils.SignEncryptUtils;
import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;

public class SignEncryptUtilsTest {

	static Provider provider = PlhCMPSystem.getProvider();
	static char[] password = PlhCMPSystem.getServerPassword();

	static X500Name subjectX500Name = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz");
	PrivateKeyHolder privateKeyHolder = new PrivateKeyHolder();
	CertificateStore certificateStore = new CertificateStore();
	@Test
	public void testSignVerify() throws Exception {
		new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withPrivateKeyHolder(privateKeyHolder)
				.withCertificateStore(certificateStore)
				.build0();

		X500Name certIssuerNameX500 = subjectX500Name;
		InputStream inputStream = new FileInputStream(
				"test/resources/rfc4210.pdf");
		FileOutputStream fileOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testSignVerify.signed");
		SignEncryptUtils.sign(privateKeyHolder, certIssuerNameX500,
				certIssuerNameX500, certificateStore, inputStream,
				fileOutputStream);
		IOUtils.closeQuietly(inputStream);
		IOUtils.closeQuietly(fileOutputStream);

		InputStream signedFileInputStream = new FileInputStream(
				"target/rfc4210.pdf.testSignVerify.signed");
		FileOutputStream verifiedOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testSignVerify.verified");
		SignEncryptUtils.verify(signedFileInputStream, certificateStore,
				verifiedOutputStream);
		boolean contentEquals = FileUtils.contentEquals(new File(
				"test/resources/rfc4210.pdf"), new File(
				"target/rfc4210.pdf.testSignVerify.verified"));
		Assert.assertTrue(contentEquals);
	}

	@Test
	public void testEncryptDecrypt() throws Exception {

		new KeyPairBuilder()
				.withEndEntityName(subjectX500Name)
				.withPrivateKeyHolder(privateKeyHolder)
				.withCertificateStore(certificateStore)
				.build0();

		List<X500Name> reciepientNamesX500 = Arrays.asList(subjectX500Name);
		InputStream encryptInputStream = new FileInputStream(
				"test/resources/rfc4210.pdf");
		FileOutputStream encryptOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testEncryptDecrypt.encrypted");
		SignEncryptUtils.encrypt(certificateStore, reciepientNamesX500,
				encryptInputStream, encryptOutputStream);
		IOUtils.closeQuietly(encryptInputStream);
		IOUtils.closeQuietly(encryptOutputStream);

		// make sure the encrypted content stream is different.
		boolean contentNotEquals = FileUtils.contentEquals(new File(
				"test/resources/rfc4210.pdf"), new File(
				"target/rfc4210.pdf.testEncryptDecrypt.encrypted"));
		Assert.assertFalse(contentNotEquals);

		PrivateKeyHolder recipientPrivateKeyHolder = privateKeyHolder;
		InputStream decryptInputStream = new FileInputStream(
				"target/rfc4210.pdf.testEncryptDecrypt.encrypted");
		OutputStream decryptOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testEncryptDecrypt.decrypted");
		SignEncryptUtils.decrypt(recipientPrivateKeyHolder, subjectX500Name,
				certificateStore, decryptInputStream, decryptOutputStream);
		IOUtils.closeQuietly(decryptInputStream);
		IOUtils.closeQuietly(decryptOutputStream);

		boolean contentEquals = FileUtils.contentEquals(new File(
				"test/resources/rfc4210.pdf"), new File(
				"target/rfc4210.pdf.testEncryptDecrypt.decrypted"));
		Assert.assertTrue(contentEquals);

	}
	
	@Test
	public void testSingEncryptDecryptVerify() throws IOException {
		new KeyPairBuilder()
			.withEndEntityName(subjectX500Name)
			.withPrivateKeyHolder(privateKeyHolder)
			.withCertificateStore(certificateStore)
			.build0();

		X500Name certIssuerX500Name = subjectX500Name;
		List<X500Name> reciepientNamesX500 = Arrays.asList(subjectX500Name);
		
		InputStream signEncryptInputStream = new FileInputStream(
				"test/resources/rfc4210.pdf");
		OutputStream signEncryptOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testSingEncryptDecryptVerify.signed.encrypted");
		SignEncryptUtils.signEncrypt(privateKeyHolder, subjectX500Name, certIssuerX500Name , 
				certificateStore, reciepientNamesX500 , signEncryptInputStream, signEncryptOutputStream);
		IOUtils.closeQuietly(signEncryptInputStream);
		IOUtils.closeQuietly(signEncryptOutputStream);
		// make sure the signed and encrypted content stream is different from original.
		boolean contentNotEquals = FileUtils.contentEquals(new File(
				"test/resources/rfc4210.pdf"), new File(
				"target/rfc4210.pdf.testSingEncryptDecryptVerify.signed.encrypted"));
		Assert.assertFalse(contentNotEquals);

		
		PrivateKeyHolder recipientPrivateKeyHolder = privateKeyHolder;
		InputStream decryptVerifyInputStream = new FileInputStream(
				"target/rfc4210.pdf.testSingEncryptDecryptVerify.signed.encrypted");
		OutputStream decryptVerifyOutputStream = new FileOutputStream(
				"target/rfc4210.pdf.testSingEncryptDecryptVerify.decrypted.verified");
		SignEncryptUtils.decryptVerify(recipientPrivateKeyHolder , certIssuerX500Name, 
				certificateStore, decryptVerifyInputStream, decryptVerifyOutputStream);
		IOUtils.closeQuietly(decryptVerifyInputStream);
		IOUtils.closeQuietly(decryptVerifyOutputStream);

		// make sure decrypted and verified file is equal to original.
		boolean contentEquals = FileUtils.contentEquals(new File(
				"test/resources/rfc4210.pdf"), new File(
				"target/rfc4210.pdf.testSingEncryptDecryptVerify.decrypted.verified"));
		Assert.assertTrue(contentEquals);
	}

	@Test
	public void testLoadData() throws Exception {
		InputStream inputStream = new FileInputStream(
				"test/resources/rfc4210.pdf");
		Assert.assertNotNull(inputStream);
	}

}
