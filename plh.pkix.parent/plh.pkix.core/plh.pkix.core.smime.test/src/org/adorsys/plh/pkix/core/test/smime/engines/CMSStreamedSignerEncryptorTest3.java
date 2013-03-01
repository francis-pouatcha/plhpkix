package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedDecryptorVerifier2;
import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedSignerEncryptor;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.jca.PasswordCallbackHandler;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

public class CMSStreamedSignerEncryptorTest3 {
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
		File signedEncryptedFile = new File("target/rfc4210.pdf.CMSStreamedSignerEncryptorTest3.signed.encrypted");
		FileOutputStream signedEncryptedOutputStream = new FileOutputStream(signedEncryptedFile);
		OutputStream signingEncryptingOutputStream = new CMSStreamedSignerEncryptor()
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.withSignerCertificateChain(privateKeyEntry.getCertificateChain())
			.withOutputStream(signedEncryptedOutputStream)
			.signingEncryptingOutputStream(privateKeyEntry.getPrivateKey());
		
		FileInputStream inputFileInputStream = new FileInputStream(inputFile);
		IOUtils.copy(inputFileInputStream, signingEncryptingOutputStream);
		IOUtils.closeQuietly(inputFileInputStream);
		IOUtils.closeQuietly(signingEncryptingOutputStream);		
		
		// make sure the signed and encrypted content stream is different from original.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, signedEncryptedFile));
		
		InputStream signedEncryptedInputStream = new FileInputStream(signedEncryptedFile);
		CMSStreamedDecryptorVerifier2 decryptorVerifier = new CMSStreamedDecryptorVerifier2()
		.withCallbackHandler(new PasswordCallbackHandler(privatekeyPass))
		.withInputStream(signedEncryptedInputStream)
		.withKeyStore(keyStore);
		InputStream decryptingInputStream =  decryptorVerifier.decryptingInputStream();
		File decryptedVerifiedFile = new File("target/rfc4210.pdf.CMSStreamedSignerEncryptorTest3.decrypted.verified");
		FileOutputStream decryptedVerifiedFileOutputStream = new FileOutputStream(decryptedVerifiedFile);
		IOUtils.copy(decryptingInputStream, decryptedVerifiedFileOutputStream);
		IOUtils.closeQuietly(decryptedVerifiedFileOutputStream);
		// make sure decrypted and verified file is equal to original.
		Assert.assertTrue(FileUtils.contentEquals(inputFile, decryptedVerifiedFile));
		
		CMSSignedMessageValidator<CMSPart> signedMessageValidator = decryptorVerifier.verify();
		
		FileCleanup.deleteQuietly(signedEncryptedFile, decryptedVerifiedFile);
	}

}
