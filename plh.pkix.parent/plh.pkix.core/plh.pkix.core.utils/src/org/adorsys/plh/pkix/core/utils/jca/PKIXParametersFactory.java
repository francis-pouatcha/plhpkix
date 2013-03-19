package org.adorsys.plh.pkix.core.utils.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public abstract class PKIXParametersFactory {

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static PKIXParameters makeParams(Set<TrustAnchor> trustAnchors, X509CRL crl, Set<CertStore> certStores){
        // create PKIXparameters
        PKIXParameters param;
		try {
			param = new PKIXParameters(trustAnchors);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(e);// keystore not initialized
		}
		
		for (CertStore certStore : certStores) {
			param.addCertStore(certStore);
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
