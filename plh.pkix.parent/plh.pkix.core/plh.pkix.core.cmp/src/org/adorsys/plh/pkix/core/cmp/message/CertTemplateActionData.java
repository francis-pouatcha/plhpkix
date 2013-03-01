package org.adorsys.plh.pkix.core.cmp.message;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;
import org.bouncycastle.asn1.crmf.CertTemplate;

public class CertTemplateActionData implements ActionData  {

	private CertTemplate certTemplate;
	
	public CertTemplate getCertTemplate() {
		return certTemplate;
	}

	public void setCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(certTemplate, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		ASN1StreamUtils.readFrom(inputStream);
	}
}
