package org.adorsys.plh.pkix.core.smime.validator;

import java.security.cert.CertPath;
import java.util.List;

import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.x509.PKIXCertPathReviewer;

public class ValidationResult {

	private PKIXCertPathReviewer review;

	private List<ErrorBundle> errors;

	private List<ErrorBundle> notifications;

	private List<?> userProvidedCerts;

	private boolean signVerified;

	ValidationResult(PKIXCertPathReviewer review, boolean verified,
			List<ErrorBundle> errors, List<ErrorBundle> notifications,
			List<?> userProvidedCerts) {
		this.review = review;
		this.errors = errors;
		this.notifications = notifications;
		signVerified = verified;
		this.userProvidedCerts = userProvidedCerts;
	}

	/**
	 * Returns a list of error messages of type {@link ErrorBundle}.
	 * 
	 * @return List of error messages
	 */
	public List<ErrorBundle> getErrors() {
		return errors;
	}

	/**
	 * Returns a list of notification messages of type {@link ErrorBundle}.
	 * 
	 * @return List of notification messages
	 */
	public List<ErrorBundle> getNotifications() {
		return notifications;
	}

	/**
	 * 
	 * @return the PKIXCertPathReviewer for the CertPath of this signature
	 *         or null if an Exception occured.
	 */
	public PKIXCertPathReviewer getCertPathReview() {
		return review;
	}

	/**
	 * 
	 * @return the CertPath for this signature or null if an Exception
	 *         occured.
	 */
	public CertPath getCertPath() {
		return review != null ? review.getCertPath() : null;
	}

	/**
	 * 
	 * @return a List of Booleans that are true if the corresponding
	 *         certificate in the CertPath was taken from the CertStore of
	 *         the SMIME message
	 */
	public List<?> getUserProvidedCerts() {
		return userProvidedCerts;
	}

	/**
	 * 
	 * @return true if the signature corresponds to the public key of the
	 *         signer
	 */
	public boolean isVerifiedSignature() {
		return signVerified;
	}

	/**
	 * 
	 * @return true if the signature is valid (ie. if it corresponds to the
	 *         public key of the signer and the cert path for the signers
	 *         certificate is also valid)
	 */
	public boolean isValidSignature() {
		if (review != null) {
			return signVerified && review.isValidCertPath()
					&& errors.isEmpty();
		} else {
			return false;
		}
	}
}
