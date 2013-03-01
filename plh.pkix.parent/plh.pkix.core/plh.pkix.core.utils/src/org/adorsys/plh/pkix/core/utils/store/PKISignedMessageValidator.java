package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.filter.TrustedInput;
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

	private static final String RESOURCE_NAME = "org.adorsys.plh.pkix.core.smime.CMSSignedMessageValidatorMessages";
	private static final Class<?> DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;
	private static final int shortKeyLength = 512;
	// (365.25*30)*24*3600*1000
	private static final long THIRTY_YEARS_IN_MILLI_SEC = 21915l * 12l * 3600l * 1000l;
	private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();
	private final Map<X509CertificateHolder, ValidationResult> results = new HashMap<X509CertificateHolder, ValidationResult>();

	/**
	 * Certificates and crls from the message
	 */
	private CertStore certs;
	/**
	 * The list of signer info from the message.
	 */
	private List<X509CertificateHolder> signerCertificates;

	private Class<?> certPathReviewerClass = DEFAULT_CERT_PATH_REVIEWER;

	/**
	 * Contains trust store and crls
	 * 
	 * The {@link PKIXParameters} from param are used for the certificate path
	 * validation.
	 */
	private PKIXParameters params;

	private BuilderChecker checker = new BuilderChecker(PKISignedMessageValidator.class);

	public PKISignedMessageValidator validate() {
		checker.checkDirty()
			.checkNull(certs,signerCertificates,params);

		// add crls and certs from mail
		params.addCertStore(certs);
		
		for (X509CertificateHolder x509CertificateHolder : signerCertificates) {
			List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
			List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();

			// signer certificate form our store.
			X509Certificate cert = null;

			try {
				List<CertStore> certStores = params.getCertStores();
				X500Name issuer = x509CertificateHolder.getIssuer();
				BigInteger serialNumber = x509CertificateHolder.getSerialNumber();
				byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(x509CertificateHolder);
				X509CertificateHolderSelector certificateHolderSelector = new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId);
				// find the signer certificate from our local store
				Collection<X509Certificate> certCollection = findCerts(
						certStores,
						selectorConverter.getCertSelector(certificateHolderSelector));
				if (!certCollection.isEmpty())
					cert = certCollection.iterator().next();
			} catch (CertStoreException cse) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"SignedMailValidator.exceptionRetrievingSignerCert",
						new Object[] { cse.getMessage(), cse,
								cse.getClass().getName() });
				errors.add(msg);
			}

			if (cert != null) {

				// check signer certificate (key length, certificate life span,
				// key usage, extended key usage)
				checkSignerCert(cert, errors, notifications);

				try {
					// construct cert chain
					CertPath certPath;
					List<?> userProvidedList;

					List<CertStore> userCertStores = new ArrayList<CertStore>();
					userCertStores.add(certs);
					Object[] cpres = createCertPath(cert,
							params.getTrustAnchors(),
							params.getCertStores(), userCertStores);
					certPath = (CertPath) cpres[0];
					userProvidedList = (List<?>) cpres[1];

					// validate cert chain
					PKIXCertPathReviewer review;
					try {
						review = (PKIXCertPathReviewer) certPathReviewerClass
								.newInstance();
					} catch (IllegalAccessException e) {
						throw new IllegalArgumentException(
								"Cannot instantiate object of type "
										+ certPathReviewerClass.getName()
										+ ": " + e.getMessage());
					} catch (InstantiationException e) {
						throw new IllegalArgumentException(
								"Cannot instantiate object of type "
										+ certPathReviewerClass.getName()
										+ ": " + e.getMessage());
					}
					review.init(certPath, params);
					if (!review.isValidCertPath()) {
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
								"SignedMailValidator.certPathInvalid");
						errors.add(msg);
					}
					results.put(x509CertificateHolder, new ValidationResult(review,
							true, errors, notifications,
							userProvidedList));
				} catch (GeneralSecurityException gse) {
					// cannot create cert path
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
							"SignedMailValidator.exceptionCreateCertPath",
							new Object[] { gse.getMessage(), gse,
									gse.getClass().getName() });
					errors.add(msg);
					results.put(x509CertificateHolder, new ValidationResult(null,
							false, errors, notifications, null));
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
						"SignedMailValidator.noSignerCert");
				errors.add(msg);
				results.put(x509CertificateHolder, new ValidationResult(null, false, errors,
						notifications, null));
			}
		}
		
		return this;
	}

	private static ASN1Primitive getObject(byte[] ext) throws IOException {
		@SuppressWarnings("resource")
		ASN1InputStream aIn = new ASN1InputStream(ext);
		ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

		aIn = new ASN1InputStream(octs.getOctets());
		return aIn.readObject();
	}

	private void checkSignerCert(X509Certificate cert,
			List<ErrorBundle> errors, List<ErrorBundle> notifications) {

		// get key length
		PublicKey key = cert.getPublicKey();
		int keyLenght = -1;
		if (key instanceof RSAPublicKey) {
			keyLenght = ((RSAPublicKey) key).getModulus().bitLength();
		} else if (key instanceof DSAPublicKey) {
			keyLenght = ((DSAPublicKey) key).getParams().getP().bitLength();
		}
		if (keyLenght != -1 && keyLenght <= shortKeyLength) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"SignedMailValidator.shortSigningKey",
					new Object[] { new Integer(keyLenght) });
			notifications.add(msg);
		}

		// warn if certificate has very long validity period
		long validityPeriod = cert.getNotAfter().getTime()
				- cert.getNotBefore().getTime();
		if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"SignedMailValidator.longValidity", new Object[] {
							new TrustedInput(cert.getNotBefore()),
							new TrustedInput(cert.getNotAfter()) });
			notifications.add(msg);
		}

		// check key usage: keyUsage must be set and have either
		// digitalSignature or nonRepudiation flag set.
		boolean[] keyUsage = cert.getKeyUsage();
		if (!(keyUsage != null && (keyUsage[0] || keyUsage[1]))) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"SignedMailValidator.signingNotPermitted");
			errors.add(msg);
		}

		// check extended key usage
		try {
			byte[] ext = cert.getExtensionValue(X509Extension.extendedKeyUsage
					.getId());
			if (ext != null) {
				ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage
						.getInstance(getObject(ext));
				if (!extKeyUsage
						.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)
						&& !extKeyUsage
								.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection)) {
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
							"SignedMailValidator.extKeyUsageNotPermitted");
					errors.add(msg);
				}
			}
		} catch (Exception e) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"SignedMailValidator.extKeyUsageError", new Object[] {
							e.getMessage(), e, e.getClass().getName() });
			errors.add(msg);
		}
	}


	private static List<X509Certificate> findCerts(List<CertStore> certStores,
			X509CertSelector selector) throws CertStoreException {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (CertStore certStore : certStores) {
			Collection<? extends Certificate> certificates = certStore
					.getCertificates(selector);
			for (Certificate certificate : certificates) {
				if (certificate instanceof X509Certificate)
					result.add((X509Certificate) certificate);
			}
		}
		return result;
	}

	private static X509Certificate findNextCert(List<CertStore> certStores,
			X509CertSelector selector, Set<X509Certificate> certSet)
			throws CertStoreException {
		List<X509Certificate> certsfound = findCerts(certStores, selector);
		for (X509Certificate certificate : certsfound) {
			if (!certSet.contains(certificate))
				return (X509Certificate) certificate;
		}
		return null;
	}

	/**
	 * 
	 * @param signerCert
	 *            the end of the path
	 * @param trustanchors
	 *            trust anchors for the path
	 * @param certStores
	 * @return the resulting certificate path.
	 * @throws GeneralSecurityException
	 */
	@SuppressWarnings({ "unused", "rawtypes" })
	private static CertPath createCertPath(X509Certificate signerCert,
			Set trustanchors, List certStores) throws GeneralSecurityException {
		Object[] results = createCertPath(signerCert, trustanchors, certStores,
				null);
		return (CertPath) results[0];
	}

	/**
	 * Returns an Object array containing a CertPath and a List of Booleans. The
	 * list contains the value <code>true</code> if the corresponding
	 * certificate in the CertPath was taken from the user provided CertStores.
	 * 
	 * @param signerCert
	 *            the end of the path
	 * @param trustanchors
	 *            trust anchors for the path
	 * @param systemCertStores
	 *            list of {@link CertStore} provided by the system
	 * @param userCertStores
	 *            list of {@link CertStore} provided by the user
	 * @return a CertPath and a List of booleans.
	 * @throws GeneralSecurityException
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static Object[] createCertPath(X509Certificate signerCert,
			Set trustanchors, List systemCertStores, List userCertStores)
			throws GeneralSecurityException {
		Set certSet = new LinkedHashSet();
		List userProvidedList = new ArrayList();

		// add signer certificate

		X509Certificate cert = signerCert;
		certSet.add(cert);
		userProvidedList.add(new Boolean(true));

		boolean trustAnchorFound = false;

		X509Certificate taCert = null;

		// add other certs to the cert path
		while (cert != null && !trustAnchorFound) {
			// check if cert Issuer is Trustanchor
			Iterator trustIt = trustanchors.iterator();
			while (trustIt.hasNext()) {
				TrustAnchor anchor = (TrustAnchor) trustIt.next();
				X509Certificate anchorCert = anchor.getTrustedCert();
				if (anchorCert != null) {
					if (anchorCert.getSubjectX500Principal().equals(
							cert.getIssuerX500Principal())) {
						try {
							cert.verify(anchorCert.getPublicKey(), "BC");
							trustAnchorFound = true;
							taCert = anchorCert;
							break;
						} catch (Exception e) {
							// trustanchor not found
						}
					}
				} else {
					if (anchor.getCAName().equals(
							cert.getIssuerX500Principal().getName())) {
						try {
							cert.verify(anchor.getCAPublicKey(), "BC");
							trustAnchorFound = true;
							break;
						} catch (Exception e) {
							// trustanchor not found
						}
					}
				}
			}

			if (!trustAnchorFound) {
				// add next cert to path
				X509CertSelector select = new X509CertSelector();
				try {
					select.setSubject(cert.getIssuerX500Principal()
							.getEncoded());
				} catch (IOException e) {
					throw new IllegalStateException(e.toString());
				}
				byte[] authKeyIdentBytes = cert
						.getExtensionValue(X509Extension.authorityKeyIdentifier
								.getId());
				if (authKeyIdentBytes != null) {
					try {
						AuthorityKeyIdentifier kid = AuthorityKeyIdentifier
								.getInstance(getObject(authKeyIdentBytes));
						if (kid.getKeyIdentifier() != null) {
							select.setSubjectKeyIdentifier(new DEROctetString(
									kid.getKeyIdentifier())
									.getEncoded(ASN1Encoding.DER));
						}
					} catch (IOException ioe) {
						// ignore
					}
				}
				boolean userProvided = false;

				cert = findNextCert(systemCertStores, select, certSet);
				if (cert == null && userCertStores != null) {
					userProvided = true;
					cert = findNextCert(userCertStores, select, certSet);
				}

				if (cert != null) {
					// cert found
					certSet.add(cert);
					userProvidedList.add(new Boolean(userProvided));
				}
			}
		}

		// if a trustanchor was found - try to find a selfsigned certificate of
		// the trustanchor
		if (trustAnchorFound) {
			if (taCert != null
					&& taCert.getSubjectX500Principal().equals(
							taCert.getIssuerX500Principal())) {
				certSet.add(taCert);
				userProvidedList.add(new Boolean(false));
			} else {
				X509CertSelector select = new X509CertSelector();

				try {
					select.setSubject(cert.getIssuerX500Principal()
							.getEncoded());
					select.setIssuer(cert.getIssuerX500Principal().getEncoded());
				} catch (IOException e) {
					throw new IllegalStateException(e.toString());
				}

				boolean userProvided = false;

				taCert = findNextCert(systemCertStores, select, certSet);
				if (taCert == null && userCertStores != null) {
					userProvided = true;
					taCert = findNextCert(userCertStores, select, certSet);
				}
				if (taCert != null) {
					try {
						cert.verify(taCert.getPublicKey(), "BC");
						certSet.add(taCert);
						userProvidedList.add(new Boolean(userProvided));
					} catch (GeneralSecurityException gse) {
						// wrong cert
					}
				}
			}
		}

		CertPath certPath = CertificateFactory.getInstance("X.509", "BC")
				.generateCertPath(new ArrayList(certSet));
		return new Object[] { certPath, userProvidedList };
	}

	public ValidationResult getValidationResult(X509CertificateHolder signer)
			throws SignedMailValidatorException {
		if (!signerCertificates.contains(signer)) {
			// the signer is not part of the SignerInformationStore
			// he has not signed the message
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"SignedMailValidator.wrongSigner");
			throw new SignedMailValidatorException(msg);
		} else {
			return (ValidationResult) results.get(signer);
		}
	}

	public PKISignedMessageValidator withCerts(CertStore certs) {
		this.certs = certs;
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
}
