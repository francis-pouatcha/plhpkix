package org.adorsys.plh.pkix.core.cmp.message;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

/**
 * We can use a key store to store a list of certificates.
 * 
 * @author francis
 *
 */
public class CertificateChainActionData implements ActionData {
	
	private CertificateChain certificateChain;

	public CertificateChainActionData(CertificateChain certificateChain) {
		this.certificateChain = certificateChain;
	}

	public CertificateChain getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(CertificateChain certificateChain) {
		this.certificateChain = certificateChain;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(certificateChain, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		ASN1StreamUtils.readFrom(inputStream);
	}
}