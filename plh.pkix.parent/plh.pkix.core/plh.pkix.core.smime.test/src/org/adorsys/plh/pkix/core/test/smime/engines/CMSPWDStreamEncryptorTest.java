package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.engines.CMSPWDStreamDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSPWDStreamEncryptor;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

public class CMSPWDStreamEncryptorTest {
	@Test
	public void test() throws Exception {

		char[] password = UUID.randomUUID().toString().toCharArray();

		File inputFile = new File("test/resources/rfc4210.pdf");
		File encryptedFile = new File("target/rfc4210.pdf.CMSPWDStreamEncryptorTest.encrypted");
		FileOutputStream encryptedFileOutputStream = new FileOutputStream(encryptedFile);
		OutputStream encryptingOutputStream = new CMSPWDStreamEncryptor()
			.withOutputStream(encryptedFileOutputStream)
			.toEncryptingOutputStream(password);
		
		FileInputStream inputFileInputStream = new FileInputStream(inputFile);
		IOUtils.copy(inputFileInputStream, encryptingOutputStream);
		IOUtils.closeQuietly(inputFileInputStream);
		IOUtils.closeQuietly(encryptingOutputStream);
		
		// make sure the encrypted content stream is different.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, encryptedFile));
		
		FileInputStream encryptedFileInputStream = new FileInputStream(encryptedFile);
		InputStream decryptingInputStream = new CMSPWDStreamDecryptor()
			.withInputStream(encryptedFileInputStream)
			.toDecryptingInputStream(password);

		File decryptedFile = new File("target/rfc4210.pdf.CMSPWDStreamEncryptorTest.decrypted.pdf");
		FileOutputStream decryptedFileOutputStream = new FileOutputStream(decryptedFile);
		IOUtils.copy(decryptingInputStream, decryptedFileOutputStream);
		IOUtils.closeQuietly(decryptingInputStream);
		IOUtils.closeQuietly(decryptedFileOutputStream);
		
		Assert.assertTrue(FileUtils.contentEquals(
				inputFile, decryptedFile));
		
		FileCleanup.deleteQuietly(encryptedFile,decryptedFile);
	}

}
