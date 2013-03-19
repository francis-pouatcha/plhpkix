package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.i18n.ErrorBundle;

public interface ExpectedSignerList {
	
	/**
	 * Check is the given certificate is presented by one of the signer's stored in this list.
	 * 
	 * @param cert
	 * @param errors
	 * @param notifications
	 */
	public void validateSigner(X509Certificate cert,
			List<ErrorBundle> errors, List<ErrorBundle> notifications);
}
