package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.CertPath;
import java.util.Collections;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.x509.PKIXCertPathReviewer;

public class ValidationResult extends ProcessingResults<X509CertificateHolder> {

	private PKIXCertPathReviewer review;

	private List<ErrorBundle> errors;

	private List<ErrorBundle> notifications;

	private List<Boolean> userProvidedCerts;

	private boolean signVerified;

	ValidationResult(PKIXCertPathReviewer review, boolean verified,
			List<ErrorBundle> errors, List<ErrorBundle> notifications,
			List<Boolean> userProvidedCerts) {
		this.review = review;
		this.errors = errors;
		this.notifications = notifications;
		this.signVerified = verified;
		this.userProvidedCerts = userProvidedCerts;
	}

	/**
	 * Returns a list of error messages of type {@link ErrorBundle}.
	 * 
	 * @return List of error messages
	 */
	public List<ErrorBundle> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	/**
	 * Returns a list of notification messages of type {@link ErrorBundle}.
	 * 
	 * @return List of notification messages
	 */
	public List<ErrorBundle> getNotifications() {
		return Collections.unmodifiableList(notifications);
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
	public List<Boolean> getUserProvidedCerts() {
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

	public void setSignVerified(boolean signVerified) {
		this.signVerified = signVerified;
	}

	@Override
	public void addError(ErrorBundle errorBundle) {
		errors.add(errorBundle);
		
	}

	@Override
	public void addNotification(ErrorBundle errorBundle) {
		notifications.add(errorBundle);
	}

	@Override
	public boolean hasError() {
		return !errors.isEmpty();
	}

	@Override
	public boolean hasNotification() {
		return !notifications.isEmpty();
	}

	@Override
	public void addErrors(List<ErrorBundle> in) {
		errors.addAll(in);
	}

	@Override
	public void addNotifications(List<ErrorBundle> in) {
		notifications.addAll(in);
	}
}
