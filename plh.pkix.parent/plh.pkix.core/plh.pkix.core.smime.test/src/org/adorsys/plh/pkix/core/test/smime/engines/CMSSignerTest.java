package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;

import org.adorsys.plh.pkix.core.smime.engines.CMSSigner;
import org.adorsys.plh.pkix.core.smime.engines.CMSVerifier;
import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;

public class CMSSignerTest {
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

		File inputFile = new File("test/resources/rfc4210.pdf");		
		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart outputPart = new CMSSigner()
			.withInputPart(inputPart)
			.withSignerCertificateChain(privateKeyEntry.getCertificateChain())
			.sign(privateKeyEntry.getPrivateKey());
		inputPart.dispose();
		
		File signedOut = new File("target/rfc4210.pdf.testSignVerify.signed");
		outputPart.writeTo(signedOut);
		outputPart.dispose();
		
		CMSPart verifiedPartIn = CMSPart.instanceFrom(signedOut);
		CMSSignedMessageValidator<CMSPart> validator = new CMSVerifier()
			.withKeyStore(keyStore)
			.withInputPart(verifiedPartIn)
			.readAndVerify();
		
		CMSPart verifiedPartOut = validator.getContent();
		File verifiedOut = new File("target/rfc4210.pdf.testSignVerify.verified");
		verifiedPartOut.writeTo(verifiedOut);
		verifiedPartIn.dispose();
		verifiedPartOut.dispose();

		Assert.assertTrue(FileUtils.contentEquals(inputFile, verifiedOut));
		
		FileCleanup.deleteQuietly(signedOut,verifiedOut);
	}

}
