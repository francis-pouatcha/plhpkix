package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.mail.internet.AddressException;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.cert.X509CertificateHolder;

public class EmailAddressExtractor implements CertInfoExtractor {

	@Override
	public List<String> extract(X509Certificate certificate) {
		X509CertificateHolder certificateHolder;
		try {
			certificateHolder = new X509CertificateHolder(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		try {
			String extractEmailAddress = X500NameHelper.extractEmailAddress(certificateHolder.getSubject());
			return Arrays.asList(extractEmailAddress);
		} catch (AddressException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
