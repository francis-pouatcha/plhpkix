package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;


public class GeneralCertValidator {

	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();
	private static final Class<?> DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;

	private Class<?> certPathReviewerClass = DEFAULT_CERT_PATH_REVIEWER;

	private List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
	private List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();

	private CertStore senderSupliedCerts;	
	private X509Certificate cert;
	private PKIXParameters params;

	private BuilderChecker checker = new BuilderChecker(GeneralCertValidator.class);

	public GeneralCertValidator validate(Date signTime) throws SignedMailValidatorException {
		checker.checkDirty().checkNull(cert,params);
		
		ValidationUtils.checkCertProperties(cert, errors, notifications);

		signTime = ValidationUtils.checkSigningTime(cert, signTime, errors, notifications);
		params.setDate(signTime);

		try {

			CertPathAndOrigin certPathAndOrigin = ValidationUtils.createCertPath(cert,
					params.getTrustAnchors(),
					params.getCertStores(), Arrays.asList(senderSupliedCerts));

			// validate cert chain
			PKIXCertPathReviewer review = ValidationUtils.createCertPathReviewer(certPathReviewerClass);
			review.init(certPathAndOrigin.getCertPath(), params);
			if (!review.isValidCertPath()) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_certPathInvalid);
				errors.add(msg);
			}
		} catch (CertPathReviewerException cpre) {
			// cannot initialize cert path reviewer - wrong parameters
			errors.add(cpre.getErrorMessage());
		}
		return this;
	}

	public GeneralCertValidator withSenderSupliedCerts(CertStore senderSupliedCerts) {
		this.senderSupliedCerts = senderSupliedCerts;
		return this;
	}

	public GeneralCertValidator withCertPathReviewerClass(Class<?> certPathReviewerClass) {
		this.certPathReviewerClass = certPathReviewerClass;
		boolean isSubclass = DEFAULT_CERT_PATH_REVIEWER
				.isAssignableFrom(certPathReviewerClass);
		if (!isSubclass) {
			throw new IllegalArgumentException(
					"certPathReviewerClass is not a subclass of "
							+ DEFAULT_CERT_PATH_REVIEWER.getName());
		}
		return this;
	}
	
	public GeneralCertValidator withPKIXParameters(PKIXParameters pkixParam){
		this.params = (PKIXParameters) pkixParam.clone(); 
		return this;
	}

	public List<ErrorBundle> getErrors() {
		return errors;
	}

	public List<ErrorBundle> getNotifications() {
		return notifications;
	}
}
