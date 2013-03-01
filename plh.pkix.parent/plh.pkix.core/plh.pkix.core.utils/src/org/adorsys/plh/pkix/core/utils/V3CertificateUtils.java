package org.adorsys.plh.pkix.core.utils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.i18n.ErrorBundle;

public class V3CertificateUtils {

	public static X509Certificate getCertificate(X509CertificateHolder holder,
			Provider provider) {
		try {
			return new JcaX509CertificateConverter().setProvider(provider)
					.getCertificate(holder);
		} catch (CertificateException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_invalidCertificate,
                    new Object[] { holder.getSubject(), holder.getIssuer() , holder.getSerialNumber()});
            throw new PlhUncheckedException(msg);
		}
	}
	
	public static X509CertificateHolder getX509CertificateHolder(Certificate certificate){
		try {
			return new X509CertificateHolder(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		} catch (IOException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	public static void checkSelfSigned(X509CertificateHolder certificateHolder, 
			byte[] subjectKeyId, byte[]  issuerKeyId, Provider provider)
					throws SecurityException{
		
		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(certificateHolder.getSubjectPublicKeyInfo());
		AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(certificateHolder.getSubjectPublicKeyInfo());
		
		boolean ckecked = Arrays.equals(subjectKeyId, subjectKeyIdentifier.getKeyIdentifier()) &&
				Arrays.equals(issuerKeyId, authorityKeyIdentifier.getKeyIdentifier());

		if (!ckecked){
			throw new SecurityException("both certificate not matching");
		}
		X509Certificate certificate = getCertificate(certificateHolder, provider);
		try {
			certificate.verify(certificate.getPublicKey());
		} catch (InvalidKeyException e) {
			throw new SecurityException(e);
		} catch (CertificateException e) {
			throw new SecurityException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(e);
		} catch (SignatureException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public static boolean isValid(X509CertificateHolder certificateHolder){
		Date notBefore = certificateHolder.getNotBefore();
		Date notAfter = certificateHolder.getNotAfter();
		Date now = new Date();
		return now.after(notBefore) && now.before(notAfter);
	}
	
	public static boolean isCaKey(X509CertificateHolder cert){
		// check is issuerCertificate is ca certificate
		Extension basicConstraintsExtension = cert.getExtension(X509Extension.basicConstraints);
		BasicConstraints issuerBasicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		if(!issuerBasicConstraints.isCA()) return false;
		
		return KeyUsageUtils.hasAllKeyUsage(cert, KeyUsage.keyCertSign);
	}

	public static boolean isSmimeKey(X509CertificateHolder cert){		
		return KeyUsageUtils.hasAnyKeyUsage(cert, KeyUsage.nonRepudiation, KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
	}
	
	public static final PublicKey extractPublicKey(X509CertificateHolder subjectCertificate) {
		try {
			return PublicKeyUtils.getPublicKey(subjectCertificate, ProviderUtils.bcProvider);
		} catch (InvalidKeySpecException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
}
