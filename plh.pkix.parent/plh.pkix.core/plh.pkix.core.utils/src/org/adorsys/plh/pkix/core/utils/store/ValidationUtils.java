package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.filter.TrustedInput;
import org.bouncycastle.x509.PKIXCertPathReviewer;

public class ValidationUtils {

	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();
	public static final int shortKeyLength = 512;
	public static final long THIRTY_YEARS_IN_MILLI_SEC = 21915l * 12l * 3600l * 1000l;
	public static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();
	
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
	 * @throws CertStoreException 
	 * @throws NoSuchProviderException 
	 * @throws CertificateException 
	 * @throws GeneralSecurityException
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static CertPathAndOrigin createCertPath(X509Certificate signerCert,
			Set<TrustAnchor> trustanchors, List<CertStore> systemCertStores, 
			List<CertStore> userCertStores) 
	{
		Set<X509Certificate> certSet = new LinkedHashSet<X509Certificate>();
		List<Boolean> userProvidedList = new ArrayList<Boolean>();

		// add signer certificate
		X509Certificate cert = signerCert;
		certSet.add(cert);
		userProvidedList.add(new Boolean(true));

		boolean trustAnchorFound = false;

		// the trust anchor certificate
		X509Certificate taCert = null;

		// add other certs to the cert path
		while (cert != null && !trustAnchorFound) {
			// check if cert Issuer is Trustanchor
			Iterator<TrustAnchor> trustIt = trustanchors.iterator();
			while (trustIt.hasNext()) {
				TrustAnchor anchor = (TrustAnchor) trustIt.next();
				trustAnchorFound = isSigningAnchor(cert, anchor);
				X509Certificate anchorCert = anchor.getTrustedCert();
				if(anchorCert!=null)taCert=anchorCert;
			}
			
			// Retrieve an intermediate certificate either from
			// the system store, or from the user store.
			if (!trustAnchorFound) {
				FoundCert signingCert = addSigningCert(cert, systemCertStores, userCertStores, certSet);
				if (signingCert != null) {
					// cert found
					certSet.add(signingCert.cert);
					userProvidedList.add(signingCert.userProvided);
				} else {
					cert = null;
				}
			}
		}

		// if a trustanchor was found - try to find a selfsigned certificate of
		// the trustanchor
		if (trustAnchorFound) {
			if (taCert != null
					&& taCert.getSubjectX500Principal().equals(
							taCert.getIssuerX500Principal())) {
				certSet.add(taCert);// root
				userProvidedList.add(new Boolean(false));
			} else {
				X509CertSelector select = new X509CertSelector();

				try {
					select.setSubject(cert.getIssuerX500Principal()
							.getEncoded());
					select.setIssuer(cert.getIssuerX500Principal().getEncoded());
				} catch (IOException e) {
					throw PlhUncheckedException.toException(e, ValidationUtils.class);
				}

				boolean userProvided = false;

				taCert = findNextCert(cert,systemCertStores, select, certSet);
				if (taCert == null && userCertStores != null) {
					userProvided = true;
					taCert = findNextCert(cert,userCertStores, select, certSet);
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
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		} catch (CertificateException e) {
			throw new PlhUncheckedException(PlhUncheckedException.toErrorMessage(e, ValidationUtils.class), e);
		} catch (NoSuchProviderException e) {
			throw new PlhUncheckedException(PlhUncheckedException.toErrorMessage(e, ValidationUtils.class), e);
		}
		
		CertPath certPath;
		try {
			certPath = certificateFactory .generateCertPath(new ArrayList(certSet));
		} catch (CertificateException e) {
			throw new PlhUncheckedException(PlhUncheckedException.toErrorMessage(e, ValidationUtils.class), e);
		}
		return new CertPathAndOrigin(certPath, userProvidedList);
	}

	public static X509Certificate findNextCert(X509Certificate cert, List<CertStore> certStores,
			X509CertSelector selector, Set<X509Certificate> notInSet)
	{
		List<X509Certificate> certsfound = findCerts(certStores, selector);
		for (X509Certificate certificate : certsfound) {
			if (notInSet.contains(certificate))continue;
			
			// verify
			try {
				cert.verify(certificate.getPublicKey(), "BC");
				return (X509Certificate) certificate;
			} catch (InvalidKeyException e) {
				// noop
			} catch (CertificateException e) {
				// noop
			} catch (NoSuchAlgorithmException e) {
				throw PlhUncheckedException.toException(e, ValidationUtils.class);
			} catch (NoSuchProviderException e) {
				throw PlhUncheckedException.toException(e, ValidationUtils.class);
			} catch (SignatureException e) {
				// noop
			}
		}
		return null;
	}
	
	public static final X509Certificate findCert(
			X509CertificateHolder x509CertificateHolder, PKIXParameters params,
			CertStore certsFromMessage, List<ErrorBundle> errors, List<ErrorBundle> notifications){
		X509Certificate cert = null;
		List<CertStore> systemCertStores = params.getCertStores();
		X500Name issuer = x509CertificateHolder.getIssuer();
		BigInteger serialNumber = x509CertificateHolder.getSerialNumber();
		byte[] subjectKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(x509CertificateHolder);
		X509CertificateHolderSelector certificateHolderSelector = new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId);
		
		// find the signer certificate from our local store
		Collection<X509Certificate> certCollection = ValidationUtils.findCerts(
				systemCertStores,
				selectorConverter.getCertSelector(certificateHolderSelector));
		if (!certCollection.isEmpty())cert = certCollection.iterator().next();
		
		if(cert==null)
			// find the signer certificate from message
			certCollection = ValidationUtils.findCerts(Arrays.asList(certsFromMessage),
					selectorConverter.getCertSelector(certificateHolderSelector));
		if (!certCollection.isEmpty())cert = certCollection.iterator().next();

		return cert;
	}
	
	public static final X509Certificate findCert(SignerInformation signer, PKIXParameters params,
			CertStore certsFromMessage, List<ErrorBundle> errors, List<ErrorBundle> notifications){
		X509Certificate cert = null;
		List<CertStore> certStores = params.getCertStores();
		// find the signer certificate from our local store
		Collection<X509Certificate> certCollection = 
				ValidationUtils.findCerts(
				certStores,
				ValidationUtils.selectorConverter.getCertSelector(signer.getSID()));
		if (!certCollection.isEmpty())cert = certCollection.iterator().next();
		
		if(cert==null)
			// find the signer certificate from message
			certCollection = ValidationUtils.findCerts(Arrays.asList(certsFromMessage),
					ValidationUtils.selectorConverter.getCertSelector(signer.getSID()));
		if (!certCollection.isEmpty())cert = certCollection.iterator().next();

		return cert;
	}
	
	public static List<X509Certificate> findCerts(List<CertStore> certStores,
			X509CertSelector selector) 
	{
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (CertStore certStore : certStores) {
			Collection<? extends Certificate> certificates;
			try {
				certificates = certStore.getCertificates(selector);
			} catch (CertStoreException cse) {
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_exceptionRetrievingSignerCert,
						cse, ValidationUtils.class);
			}
			for (Certificate certificate : certificates) {
				if (certificate instanceof X509Certificate)
					result.add((X509Certificate) certificate);
			}
		}
		return result;
	}
	

	public static ASN1Primitive getObject(byte[] ext) throws IOException {
		@SuppressWarnings("resource")
		ASN1InputStream aIn = new ASN1InputStream(ext);
		ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

		aIn = new ASN1InputStream(octs.getOctets());
		return aIn.readObject();
	}
	
	private static boolean isSigningAnchor(X509Certificate cert, TrustAnchor anchor){
		X509Certificate anchorCert = anchor.getTrustedCert();
		if (anchorCert != null) {
			if (anchorCert.getSubjectX500Principal().equals(
					cert.getIssuerX500Principal())) {
				try {
					cert.verify(anchorCert.getPublicKey(), "BC");
					return true;
				} catch (Exception e) {
					return false;
				}
			}
		} else {
			if (anchor.getCAName().equals(
					cert.getIssuerX500Principal().getName())) {
				try {
					cert.verify(anchor.getCAPublicKey(), "BC");
					return true;
				} catch (Exception e) {
					return false;
				}
			}
		}		
		
		return false;
	}
	
	private static FoundCert addSigningCert(
			X509Certificate cert, 
			final List<CertStore> systemCertStores,
			final List<CertStore> userCertStores,
			final Set<X509Certificate> certChain 
			) 
	{
		// add next cert to path
		X509CertSelector select = new X509CertSelector();
		try {
			select.setSubject(cert.getIssuerX500Principal()
					.getEncoded());
		} catch (IOException e) {
			throw PlhUncheckedException.toException(e, ValidationUtils.class);
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

		X509Certificate signerCert = findNextCert(cert, systemCertStores, select, certChain);
		if (signerCert == null && userCertStores != null) {
			userProvided = true;
			signerCert = findNextCert(cert, userCertStores, select, certChain);
		}
		if (signerCert != null) {
			return new FoundCert(signerCert, userProvided);
		}
		return null;		
	}
	
	static class FoundCert{
		final X509Certificate cert;
		final Boolean userProvided;
		public FoundCert(X509Certificate signerCert, Boolean userProvided) {
			super();
			this.cert = signerCert;
			this.userProvided = userProvided;
		}
	}
	
	
	public static Date getSignatureTime(SignerInformation signer) {
		AttributeTable atab = signer.getSignedAttributes();
		Date result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.signingTime);
			if (attr != null) {
				Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0)
						.toASN1Primitive());
				result = t.getDate();
			}
		}
		return result;
	}

	public static void checkCertProperties(X509Certificate cert,
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
					PlhPkixCoreMessages.SignatureValidator_shortSigningKey,
					new Object[] { new Integer(keyLenght) });
			notifications.add(msg);
		}

		// warn if certificate has very long validity period
		long validityPeriod = cert.getNotAfter().getTime()
				- cert.getNotBefore().getTime();
		if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_longValidity, new Object[] {
							new TrustedInput(cert.getNotBefore()),
							new TrustedInput(cert.getNotAfter()) });
			notifications.add(msg);
		}

		// check key usage: keyUsage must be set and have either
		// digitalSignature or nonRepudiation flag set.
		boolean[] keyUsage = cert.getKeyUsage();
		if (!(keyUsage != null && (keyUsage[0] || keyUsage[1]))) {
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_signingNotPermitted);
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
							PlhPkixCoreMessages.SignatureValidator_extKeyUsageNotPermitted);
					errors.add(msg);
				}
			}
		} catch (Exception e) {
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_extKeyUsageError, e, ValidationUtils.class);
		}
	}
	
	public static PKIXCertPathReviewer createCertPathReviewer(Class<?> certPathReviewerClass){
		try {
			return (PKIXCertPathReviewer) certPathReviewerClass
					.newInstance();
		} catch (IllegalAccessException e) {
			throw PlhUncheckedException.toException(e, ValidationUtils.class);
		} catch (InstantiationException e) {
			throw PlhUncheckedException.toException(e, ValidationUtils.class);
		}
	}
	
	public static final Date checkSigningTime(X509Certificate cert, Date signTime,
			List<ErrorBundle> errors, List<ErrorBundle> notifications){
		if (signTime == null) // no signing time was found
		{
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					PlhPkixCoreMessages.SignatureValidator_noSigningTime);
			errors.add(msg);
			signTime = new Date();
		} else {
			// check if certificate was valid at signing time
			try {
				cert.checkValidity(signTime);
			} catch (CertificateExpiredException e) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_certExpired,
						new Object[] { new TrustedInput(signTime),
								new TrustedInput(cert.getNotAfter()) });
				errors.add(msg);
			} catch (CertificateNotYetValidException e) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						PlhPkixCoreMessages.SignatureValidator_certNotYetValid,
						new Object[] { new TrustedInput(signTime),
								new TrustedInput(cert.getNotBefore()) });
				errors.add(msg);
			}
		}		
		
		return signTime;
	}
}
