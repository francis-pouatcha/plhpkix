package org.adorsys.plh.pkix.core.cmp.message;

import org.adorsys.plh.pkix.core.utils.action.ErrorsAndNotificationsHolder;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateValidatingProcessingResult<T> extends ProcessingResults<T> {
	
	private X509CertificateHolder certificateHolder;
	
	private PKISignedMessageValidator validator;
	
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
	public PKISignedMessageValidator getValidator() {
		return validator;
	}
	public void setValidator(PKISignedMessageValidator validator) {
		this.validator = validator;
	}
	@Override
	public boolean hasError() {
		if(validator!=null && validator.hasError()) return true;
		return super.hasError();
	}
	@Override
	public boolean hasNotification() {
		if(validator!=null && validator.hasNotification()) return true;
		return super.hasNotification();
	}
}
