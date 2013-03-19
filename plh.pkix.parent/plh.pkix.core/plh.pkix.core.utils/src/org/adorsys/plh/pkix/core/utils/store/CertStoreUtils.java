package org.adorsys.plh.pkix.core.utils.store;

import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.util.Store;

public class CertStoreUtils {
	
	public static CertStore toCertStore(Store certificatesStore){
        JcaCertStoreBuilder jcaCertStoreBuilder = new JcaCertStoreBuilder();
		jcaCertStoreBuilder.addCertificates(certificatesStore);
		try {
			return jcaCertStoreBuilder.build();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}		
	}
	
	public static List<X509CertificateHolder> toCertHolders(Store certificatesStore){
		@SuppressWarnings("rawtypes")
		Collection matches = certificatesStore.getMatches(null);
		List<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
		for (Object object : matches) {
			if(object instanceof X509CertificateHolder)
				result.add((X509CertificateHolder)object);
		}
		return result;
	}
	
}
