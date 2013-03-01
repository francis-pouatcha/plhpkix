package org.adorsys.plh.pkix.core.utils.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public abstract class PKIXParametersFactory {

	public static PKIXParameters makeParams(KeyStoreWraper keystoreWraper) throws KeyStoreException, InvalidAlgorithmParameterException{
		// add self signed certificate
		Set<TrustAnchor> hashSet = new HashSet<TrustAnchor>();
		Enumeration<String> aliases = keystoreWraper.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (keystoreWraper.isKeyEntry(alias) || keystoreWraper.isCertificateEntry(alias)) {
				Certificate cert = keystoreWraper.getCertificate(alias);
				if(cert==null) continue;
				if (cert instanceof X509Certificate)
					hashSet.add(new TrustAnchor((X509Certificate) cert, null));
			}
		}
		return new PKIXParameters(hashSet);
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static PKIXParameters makeParams(KeyStoreWraper keyStoreWraper, X509CRL crl){
        // create PKIXparameters
        PKIXParameters param;
		try {
			param = PKIXParametersFactory.makeParams(keyStoreWraper);
		} catch (KeyStoreException e) {
			throw new IllegalArgumentException(e);// keystore not initialized
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(e);// keystore not initialized
		}

        // load one ore more crls from files (here we only load one crl)
        if (crl != null)
        {
            List crls = new ArrayList();
			crls.add(crl);
			CertStore certStore;
			try {
				certStore = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(crls), "BC");
				// add crls and enable revocation checking
				param.addCertStore(certStore);
				param.setRevocationEnabled(true);
			} catch (InvalidAlgorithmParameterException e) {
				throw new IllegalStateException(e);// keystore not initialized
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);// keystore not initialized
			} catch (NoSuchProviderException e) {
				throw new IllegalStateException(e);// keystore not initialized
			}
        } else {
			param.setRevocationEnabled(false);
        }
        return param;
	}
}
