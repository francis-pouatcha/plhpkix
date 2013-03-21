package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;

/**
 * Check certificates for their validity. 
 * 
 * @author francis
 *
 */
public class PKISignedMessageValidator {

	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();
	private static final Class<?> DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;
	
	private final Map<X509CertificateHolder, ValidationResult> results = new HashMap<X509CertificateHolder, ValidationResult>();

	/**
	 * Certificates and crls from the message
	 */
	private CertStore certsFromMessage;
	
	/**
	 * The list of signer info from the message.
	 */
	private List<X509CertificateHolder> signerCertificates;

	private Class<?> certPathReviewerClass = DEFAULT_CERT_PATH_REVIEWER;

	/**
	 * list of expected senders
	 */
	private ExpectedSignerList signerList;// can be null

	/**
	 * Contains trust store and crls
	 * 
	 * The {@link PKIXParameters} from param are used for the certificate path
	 * validation.
	 */
	private PKIXParameters params;

	private BuilderChecker checker = new BuilderChecker(PKISignedMessageValidator.class);

	/**
	 * Validate the certificates, but does not verify the signature.
	 * @return
	 */
	public PKISignedMessageValidator validate(Date signTime) {
		checker.checkDirty()
			.checkNull(certsFromMessage,signerCertificates,params);

		for (X509CertificateHolder x509CertificateHolder : signerCertificates) {
			List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
			List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();

			// signer certificate form our store.
			X509Certificate cert = ValidationUtils.findCert(x509CertificateHolder, params, certsFromMessage, errors, notifications);

			if (cert != null) {

				if(signerList!=null)
					signerList.validateSigner(cert, errors, notifications);

				// check signer certificate (key length, certificate life span,
				// key usage, extended key usage)
				ValidationUtils.checkCertProperties(cert, errors, notifications);

				// check certificate path
				// get signing time if possible, otherwise use current time as
				// signing time
				signTime = ValidationUtils.checkSigningTime(cert, signTime, errors, notifications);
				params.setDate(signTime);
				
				try {
					// construct cert chain
					List<CertStore> userCertStores = new ArrayList<CertStore>();
					userCertStores.add(certsFromMessage);
					CertPathAndOrigin certPathAndOrigin = ValidationUtils.createCertPath(cert,
							params.getTrustAnchors(),
							params.getCertStores(), userCertStores);

					// validate cert chain
					PKIXCertPathReviewer review =ValidationUtils.createCertPathReviewer(certPathReviewerClass);
					review.init(certPathAndOrigin.getCertPath(), params);
					if (!review.isValidCertPath()) {
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
								PlhPkixCoreMessages.SignatureValidator_certPathInvalid);
						errors.add(msg);
					}
					results.put(x509CertificateHolder, new ValidationResult(review,
							true, errors, notifications,
							certPathAndOrigin.getUserProvidedFlags()));
				} catch (CertPathReviewerException cpre) {
					// cannot initialize certpathreviewer - wrong parameters
					errors.add(cpre.getErrorMessage());
					results.put(x509CertificateHolder, new ValidationResult(null,
							false, errors, notifications, null));
				}
			} else
			// no signer certificate found
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_noSignerCert);
				errors.add(msg);
				results.put(x509CertificateHolder, new ValidationResult(null, false, errors,
						notifications, null));
			}
		}
		return this;
	}

	public ValidationResult getValidationResult(X509CertificateHolder signer)
			throws SignedMailValidatorException {
		if (!signerCertificates.contains(signer)) {
			// the signer is not part of the SignerInformationStore
			// he has not signed the message
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_wrongSigner);
			throw new SignedMailValidatorException(msg);
		} else {
			return results.get(signer);
		}
	}

	public PKISignedMessageValidator withCerts(CertStore certs) {
		this.certsFromMessage = certs;
		return this;
	}

	public PKISignedMessageValidator withSignerCertificates(List<X509CertificateHolder> signers) {
		this.signerCertificates = signers;
		return this;
	}

	public PKISignedMessageValidator withCertPathReviewerClass(Class<?> certPathReviewerClass) {
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

	public PKISignedMessageValidator withPKIXParameters(PKIXParameters pkixParam){
		this.params = (PKIXParameters) pkixParam.clone(); 
		return this;
	}

	public PKISignedMessageValidator withSignerList(ExpectedSignerList signerList) {
		this.signerList = signerList;
		return this;
	}
	
	public boolean hasError() {
		if(results==null) return false;
		Collection<ValidationResult> values = results.values();
		for (ValidationResult validationResult : values) {
			if(validationResult.hasError()) return true;
		}
		return false;
	}

	public boolean hasNotification() {
		if(results==null) return false;
		Collection<ValidationResult> values = results.values();
		for (ValidationResult validationResult : values) {
			if(validationResult.hasNotification()) return true;
		}
		return false;
	}
}
