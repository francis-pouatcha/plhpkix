package org.adorys.plh.pkix.core.cmp.utils;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class V3CertificateUtils {

	public static X509CertificateHolder makeSelfV3Certificate(
			KeyPair subjectKeyPair, X500Name subject, Date notBefore,
			Date notAfter, Provider provider)  {
		try {
			PublicKey subPub = subjectKeyPair.getPublic();
			PrivateKey issPriv = subjectKeyPair.getPrivate();
			PublicKey issPub = subjectKeyPair.getPublic();

			X500Name issuer = subject;
			BigInteger serial = UUIDUtils.toBigInteger(UUID.randomUUID());

			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
					issuer, serial, notBefore, notAfter, subject, subPub);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(subPub));

			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(issPub));

			v3CertGen.addExtension(X509Extension.basicConstraints, true,
					new BasicConstraints(0));

			// GeneralNames subjectAltName = new GeneralNames(new GeneralName(
			// GeneralName.rfc822Name, email));
			// v3CertGen.addExtension(X509Extension.subjectAlternativeName,
			// false,
			// subjectAltName);

			ContentSigner signer;
			try {
				signer = new JcaContentSignerBuilder("SHA1WithRSA")
						.setProvider(provider).build(issPriv);
			} catch (OperatorCreationException e) {
				throw new IllegalStateException(e);
			}
			return v3CertGen.build(signer);
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static X509CertificateHolder makeV3Certificate(
			X509CertificateHolder subjectCertificate,
			PrivateKey issuerPrivatekey,
			X509CertificateHolder issuerCertificate, Date notBefore,
			Date notAfter, Provider provider) {
		try {
			PublicKey subPub;
			try {
				subPub = PublicKeyUtils.getPublicKey(subjectCertificate,
						provider);
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}

			X500Name subjectDN = subjectCertificate.getSubject();
			X500Name issuerDN = issuerCertificate.getSubject();
			BigInteger serial = UUIDUtils.toBigInteger(UUID.randomUUID());
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
					issuerDN, serial, notBefore, notAfter, subjectDN, subPub);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(subPub));

			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(issuerCertificate));

			v3CertGen.addExtension(X509Extension.basicConstraints, true,
					new BasicConstraints(false));

			// GeneralNames subjectAltName = new GeneralNames(new
			// GeneralName(GeneralName.rfc822Name, email));
			// v3CertGen.addExtension(X509Extension.subjectAlternativeName,
			// false, subjectAltName);

			ContentSigner signer;
			try {
				signer = new JcaContentSignerBuilder("SHA1WithRSA")
						.setProvider(provider).build(issuerPrivatekey);
			} catch (OperatorCreationException e) {
				throw new IllegalStateException(e);
			}

			return v3CertGen.build(signer);
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static X509CertificateHolder makeV3Certificate(
			PublicKey subjectPublicKey, X500Name subjectDN,
			PrivateKey issuerPrivatekey,
			X509CertificateHolder issuerCertificate, Date notBefore,
			Date notAfter, Provider provider) {

		try {
			X500Name issuerDN = issuerCertificate.getSubject();
			BigInteger serial = UUIDUtils.toBigInteger(UUID.randomUUID());
			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
					issuerDN, serial, notBefore, notAfter, subjectDN,
					subjectPublicKey);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(subjectPublicKey));

			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(issuerCertificate));

			v3CertGen.addExtension(X509Extension.basicConstraints, true,
					new BasicConstraints(false));

			// GeneralNames subjectAltName = new GeneralNames(new
			// GeneralName(GeneralName.rfc822Name, email));
			// v3CertGen.addExtension(X509Extension.subjectAlternativeName,
			// false, subjectAltName);

			ContentSigner signer;
			try {
				signer = new JcaContentSignerBuilder("SHA1WithRSA")
						.setProvider(provider).build(issuerPrivatekey);
			} catch (OperatorCreationException e) {
				throw new IllegalStateException(e);
			}

			return v3CertGen.build(signer);
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static X509Certificate getCertificate(X509CertificateHolder holder,
			Provider provider) {
		try {
			return new JcaX509CertificateConverter().setProvider(provider)
					.getCertificate(holder);
		} catch (CertificateException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public static void checkSelfSigned(X509CertificateHolder certificateHolder, 
			String subjectCN, String isuerCN, Provider provider)
					throws SecurityException{
		String providedSectCN = X500NameHelper.getCN(certificateHolder.getSubject());
		String providedIssuerCN = X500NameHelper.getCN(certificateHolder.getIssuer());
		if (!StringUtils.equalsIgnoreCase(subjectCN, providedSectCN) ||
				!StringUtils.equalsIgnoreCase(isuerCN, providedIssuerCN)){
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
}
