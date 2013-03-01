package org.adorsys.plh.pkix.core.cmp.message;

import org.adorsys.plh.pkix.core.utils.action.ErrorsAndNotificationsHolder;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateValidatingProcessingResult<T> extends ProcessingResults<T> {
	
	private X509CertificateHolder certificateHolder;
	
	private ValidationResult validationResult;
	
	
	public CertificateValidatingProcessingResult() {
		super();
	}
	public CertificateValidatingProcessingResult(
			ErrorsAndNotificationsHolder clone) {
		super(clone);
	}
	public CertificateValidatingProcessingResult(ProcessingResults<T> clone) {
		super(clone);
	}
	
	public X509CertificateHolder getCertificateHolder() {
		return certificateHolder;
	}
	
	public void setCertificateHolder(X509CertificateHolder certificateHolder) {
		this.certificateHolder = certificateHolder;
	}
	
	public ValidationResult getValidationResult() {
		return validationResult;
	}
	
	public void setValidationResult(ValidationResult validationResult) {
		this.validationResult = validationResult;
	}
	
	
}
