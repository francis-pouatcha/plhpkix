package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.CertPath;
import java.util.List;

public class CertPathAndOrigin {

	private final CertPath certPath;
	
	private final List<Boolean> userProvidedFlags;

	public CertPathAndOrigin(CertPath certPath, List<Boolean> userProvidedFlags) {
		super();
		this.certPath = certPath;
		this.userProvidedFlags = userProvidedFlags;
	}

	public CertPath getCertPath() {
		return certPath;
	}

	public List<Boolean> getUserProvidedFlags() {
		return userProvidedFlags;
	}
}
