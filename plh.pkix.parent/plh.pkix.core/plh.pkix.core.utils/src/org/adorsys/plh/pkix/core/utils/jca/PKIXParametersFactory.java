package org.adorsys.plh.pkix.core.utils.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public abstract class PKIXParametersFactory {

	public static PKIXParameters create(KeyStore keystore) throws KeyStoreException, InvalidAlgorithmParameterException{
		// add self signed certificate
		Set<TrustAnchor> hashSet = new HashSet<TrustAnchor>();
		Enumeration<String> aliases = keystore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (keystore.isKeyEntry(alias) || keystore.isCertificateEntry(alias)) {
				Certificate cert = keystore.getCertificate(alias);
				if(cert==null) continue;
				if (cert instanceof X509Certificate)
					hashSet.add(new TrustAnchor((X509Certificate) cert, null));
			}
		}
		return new PKIXParameters(hashSet);
	}
}
