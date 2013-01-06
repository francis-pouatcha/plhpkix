package org.adorys.plh.pkix.server.cmp.core.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class V3CertificateUtils {

	public static X509CertificateHolder makeSelfV3Certificate(KeyPair subKP,
			String _subDN, KeyPair issKP, String _issDN, Provider provider) {

		PublicKey subPub = subKP.getPublic();
		PrivateKey issPriv = issKP.getPrivate();

		X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
				new X500Name(_issDN), BigInteger.valueOf(System
						.currentTimeMillis()), new Date(
						System.currentTimeMillis()), new Date(
						System.currentTimeMillis()
								+ (1000L * 60 * 60 * 24 * 100)), new X500Name(
						_subDN), subPub);

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
					provider).build(issPriv);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v1CertGen.build(signer);
	}

	public static X509CertificateHolder makeSelfV3Certificate(
			KeyPair subKP,
			X500Name _subDN, 
			KeyPair issKP, 
			X500Name _issDN, 
			Date notBefore,
			Date notAfter,
			Provider provider) {

		PublicKey subPub = subKP.getPublic();
		PrivateKey issPriv = issKP.getPrivate();

		X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
				_issDN,// issuer 
				BigInteger.valueOf(System.currentTimeMillis()), // Serial
				notBefore, 
				notAfter, 
				_subDN, 
				subPub
		);

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
					provider).build(issPriv);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v1CertGen.build(signer);
	}
	
	public static X509CertificateHolder makeV3Certificate(
			X509CertificateHolder subjectCertificate,
			PrivateKey issuerPrivatekey, String _issDN, Provider provider) {

		PublicKey subPub;
		try {
			subPub = PublicKeyUtils.getPublicKey(subjectCertificate, provider);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		X500Name subjectDN = subjectCertificate.getSubject();

		X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
				new X500Name(_issDN), BigInteger.valueOf(System
						.currentTimeMillis()), new Date(
						System.currentTimeMillis()), new Date(
						System.currentTimeMillis()
								+ (1000L * 60 * 60 * 24 * 100)), subjectDN,
				subPub);

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
					provider).build(issuerPrivatekey);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v1CertGen.build(signer);
	}

	public static X509CertificateHolder makeSelfV3Certificate(
			X509CertificateHolder subjectCertificate,
			X500Name _subDN, 
			PrivateKey issuerPrivatekey, 
			X500Name _issDN, 
			Date notBefore,
			Date notAfter,
			Provider provider) {

		PublicKey subPub;
		try {
			subPub = PublicKeyUtils.getPublicKey(subjectCertificate, provider);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
				_issDN,// issuer 
				BigInteger.valueOf(System.currentTimeMillis()), // Serial
				notBefore, 
				notAfter, 
				_subDN, 
				subPub
		);

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
					provider).build(issuerPrivatekey);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v1CertGen.build(signer);
	}

	
	public static X509CertificateHolder makeSelfV3Certificate(
			PublicKey subjectPublicKey,
			X500Name _subDN, 
			PrivateKey issuerPrivatekey, 
			X500Name _issDN, 
			Date notBefore,
			Date notAfter,
			Provider provider) {

		X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
				_issDN,// issuer 
				BigInteger.valueOf(System.currentTimeMillis()), // Serial
				notBefore, 
				notAfter, 
				_subDN, 
				subjectPublicKey
		);

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
					provider).build(issuerPrivatekey);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v1CertGen.build(signer);
	}
	
	public static X509Certificate getCertificate(X509CertificateHolder holder, Provider provider){
		try {
			return new JcaX509CertificateConverter().setProvider(provider)
					.getCertificate(holder);
		} catch (CertificateException e) {
			throw new IllegalStateException(e);
		}
	}
}
