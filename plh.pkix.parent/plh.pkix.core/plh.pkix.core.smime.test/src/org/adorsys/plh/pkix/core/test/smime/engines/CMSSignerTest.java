package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSSigner;
import org.adorsys.plh.pkix.core.smime.engines.CMSVerifier;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;

public class CMSSignerTest {
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

		File inputFile = new File("test/resources/rfc4210.pdf");		
		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart outputPart = new CMSSigner()
			.withInputPart(inputPart)
			.sign(privateKeyEntry);
		inputPart.dispose();
		
		File signedOut = new File("target/rfc4210.pdf.testSignVerify.signed");
		outputPart.writeTo(signedOut);
		outputPart.dispose();
		
		CMSPart verifiedPartIn = CMSPart.instanceFrom(signedOut);
		CMSSignedMessageValidator<CMSPart> validator = new CMSVerifier()
			.withContactManager(contactManager)
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
