package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * extract a given information from the certificate.
 * For example: the email address associated with the certificate.
 * 
 * @author francis
 *
 */
public interface CertInfoExtractor {
	public List<String> extract(X509Certificate certificate);
}
