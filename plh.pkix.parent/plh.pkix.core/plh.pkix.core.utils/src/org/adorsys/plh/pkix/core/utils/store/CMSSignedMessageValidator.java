package org.adorsys.plh.pkix.core.utils.store;

import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;

/**
 * Check certificates for their validity. Additionally if the list of
 * senders and the certificate info extractor is set, we use the info
 * extractor form the certificate to read the sender identifier as specified
 * by certificate and make sure the identifier is contained in the list of
 * senders. An error is thrown if there is one sender in the list without a
 * corresponding signers entry.
 * 
 * @author francis
 *
 */
public class CMSSignedMessageValidator <T>{
	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();
	private static final Class<?> DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;

	private final Map<SignerInformation, ValidationResult> results = new HashMap<SignerInformation, ValidationResult>();

	/**
	 * Certificates and crls from the message
	 */
	private CertStore certsFromMessage;
	/**
	 * The list of signer info from the message.
	 */
	private SignerInformationStore signers;

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
	
	/**
	 * The extracted content, for encapsulated messages.
	 */
	private T content;

	private BuilderChecker checker = new BuilderChecker(CMSSignedMessageValidator.class);

	/**
	 * Validate the certificates and verify the signature.
	 * 
	 * @return
	 * @throws SignedMailValidatorException
	 */
	public CMSSignedMessageValidator<T> validate() throws SignedMailValidatorException {
		checker.checkDirty()
			.checkNull(signers,params);

		@SuppressWarnings("unchecked")
		Collection<SignerInformation> signerInfoList = signers.getSigners();
		for (SignerInformation signer : signerInfoList) {
			List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
			List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();

			// signer certificate
			X509Certificate cert = ValidationUtils.findCert(signer, params, certsFromMessage, errors, notifications);

			if (cert != null) {
				// check signature
				boolean validSignature = false;
				try {
					SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
							.build(cert);
					validSignature = signer.verify(signerInformationVerifier);
					if (!validSignature) {
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
								PlhPkixCoreMessages.SignatureValidator_signatureNotVerified);
						errors.add(msg);
					}
				} catch (Exception e) {
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
							PlhPkixCoreMessages.SignatureValidator_exceptionVerifyingSignature,
							new Object[] { e.getMessage(), e,
									e.getClass().getName() });
					errors.add(msg);
				}
				
				if(signerList!=null)
					signerList.validateSigner(cert, errors, notifications);

				// check signer certificate (key length, certificate life span,
				// key usage, extended key usage)
				ValidationUtils.checkCertProperties(cert, errors, notifications);

				// notify if a signed receipt request is in the message
				AttributeTable atab = signer.getSignedAttributes();
				if (atab != null) {
					Attribute attr = atab
							.get(PKCSObjectIdentifiers.id_aa_receiptRequest);
					if (attr != null) {
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
								PlhPkixCoreMessages.SignatureValidator_signedReceiptRequest);
						notifications.add(msg);
					}
				}

				// check certificate path
				// get signing time if possible, otherwise use current time as
				// signing time
				Date signTime = ValidationUtils.getSignatureTime(signer);
				signTime = ValidationUtils.checkSigningTime(cert, signTime, errors, notifications);
				params.setDate(signTime);

				try {
					CertPathAndOrigin certPathAndOrigin = ValidationUtils.createCertPath(cert,
							params.getTrustAnchors(),
							params.getCertStores(), Arrays.asList(certsFromMessage));

					// validate cert chain
					PKIXCertPathReviewer review = ValidationUtils.createCertPathReviewer(certPathReviewerClass);;
					review.init(certPathAndOrigin.getCertPath(), params);
					if (!review.isValidCertPath()) {
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
								PlhPkixCoreMessages.SignatureValidator_certPathInvalid);
						errors.add(msg);
					}
					results.put(signer, new ValidationResult(review,
							validSignature, errors, notifications,
							certPathAndOrigin.getUserProvidedFlags()));
				} catch (CertPathReviewerException cpre) {
					// cannot initialize certpathreviewer - wrong parameters
					errors.add(cpre.getErrorMessage());
					results.put(signer, new ValidationResult(null,
							validSignature, errors, notifications, null));
				}
			} else
			// no signer certificate found
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_noSignerCert);
				errors.add(msg);
				results.put(signer, new ValidationResult(null, false, errors,
						notifications, null));
			}
		}
		
		return this;
	}
	
	public ValidationResult getValidationResult(SignerInformation signer)
			throws SignedMailValidatorException {
		if (signers.getSigners(signer.getSID()).isEmpty()) {
			// the signer is not part of the SignerInformationStore
			// he has not signed the message
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_wrongSigner);
			throw new SignedMailValidatorException(msg);
		} else {
			return (ValidationResult) results.get(signer);
		}
	}

	public CMSSignedMessageValidator<T> withCertsFromMessage(CertStore certs) {
		this.certsFromMessage = certs;
		return this;
	}

	public CMSSignedMessageValidator<T> withSigners(SignerInformationStore signers) {
		this.signers = signers;
		return this;
	}

	public CMSSignedMessageValidator<T> withCertPathReviewerClass(Class<?> certPathReviewerClass) {
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

	public CMSSignedMessageValidator<T> withSignerList(ExpectedSignerList signerList) {
		this.signerList = signerList;
		return this;
	}
	public CMSSignedMessageValidator<T> withContent(T content) {
		this.content = content;
		return this;
	}
	
	public CMSSignedMessageValidator<T> withPKIXParameters(PKIXParameters pkixParam){
		this.params = (PKIXParameters) pkixParam.clone(); 
		return this;
	}

	public T getContent() {
		return content;
	}

	public void setContent(T content) {
		this.content = content;
	}
}
