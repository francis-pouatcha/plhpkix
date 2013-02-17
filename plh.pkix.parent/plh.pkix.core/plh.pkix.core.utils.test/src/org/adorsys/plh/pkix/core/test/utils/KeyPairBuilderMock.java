package org.adorsys.plh.pkix.core.test.utils;

import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyPairAndCertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;

public class KeyPairBuilderMock extends KeyPairBuilder{

	@Override
	protected KeyPairAndCertificateHolder generateSelfSignedKeyPair(
			X500Name x500Name) {
		return super.generateSelfSignedKeyPair(x500Name);
	}
	
}
