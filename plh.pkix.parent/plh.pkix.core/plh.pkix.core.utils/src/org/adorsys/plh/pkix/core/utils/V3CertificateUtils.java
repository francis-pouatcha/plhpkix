package org.adorsys.plh.pkix.core.utils;

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
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
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

	public static X509CertificateHolder makeSelfV3Certificate0(boolean isCa,
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

	public static X509CertificateHolder makeV3Certificate0(
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

	public static X509CertificateHolder makeV3Certificate0(
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
	
	public static boolean isValide(X509CertificateHolder certificateHolder){
		Date notBefore = certificateHolder.getNotBefore();
		Date notAfter = certificateHolder.getNotAfter();
		Date now = new Date();
		return now.after(notBefore) && now.before(notAfter);
	}
}
