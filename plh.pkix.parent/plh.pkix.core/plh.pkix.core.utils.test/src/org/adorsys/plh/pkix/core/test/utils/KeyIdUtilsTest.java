package org.adorsys.plh.pkix.core.test.utils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.store.KeyPairAndCertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.Assert;
import org.junit.Test;

public class KeyIdUtilsTest {

	@Test
	public void testGetSubjectKeyIdentifierAsByteString() throws NoSuchAlgorithmException, IOException {
		KeyPairAndCertificateHolder keyPairAndCertificateHolder = new KeyPairBuilderMock().generateSelfSignedKeyPair(new X500Name("cn=test"));
		X509CertificateHolder subjectCertificateHolder = keyPairAndCertificateHolder.getSubjectCertificateHolder();
		byte[] byteString = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCertificateHolder);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectCertificateHolder.getSubjectPublicKeyInfo());
		Assert.assertArrayEquals(byteString, subjectKeyIdentifier.getKeyIdentifier());
	}
}
