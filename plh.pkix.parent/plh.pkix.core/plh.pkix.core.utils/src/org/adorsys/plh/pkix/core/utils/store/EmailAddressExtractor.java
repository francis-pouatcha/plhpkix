package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.X509Certificate;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.cert.X509CertificateHolder;

public class EmailAddressExtractor implements CertInfoExtractor {

	@Override
	public List<String> extract(X509Certificate certificate) {
		X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
		return X500NameHelper.readSubjectEmails(certHolder);
	}

}
