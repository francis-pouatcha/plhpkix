package org.adorsys.plh.pkix.core.utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class V3CertificateUtils {

	public static X509Certificate getX509JavaCertificate(X509CertificateHolder holder) {
		try {
			return new JcaX509CertificateConverter().setProvider(ProviderUtils.bcProvider)
					.getCertificate(holder);
		} catch (CertificateException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_invalidCertificate,
                    new Object[] { holder.getSubject(), holder.getIssuer() , holder.getSerialNumber()});
            throw new PlhUncheckedException(msg);
		}
	}
	public static org.bouncycastle.asn1.x509.Certificate getX509BCCertificate(X509CertificateHolder certHolder){
		return certHolder.toASN1Structure();
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

	public static X509Certificate getX509JavaCertificate(org.bouncycastle.asn1.x509.Certificate certificate) {
		return getX509JavaCertificate(new X509CertificateHolder(certificate));
	}
	
	public static X509Certificate[] convert(org.bouncycastle.asn1.x509.Certificate...certificates){
		X509Certificate[] list = new X509Certificate[certificates.length];
		for (int i = 0; i < certificates.length; i++) {
			list[i]=getX509JavaCertificate(certificates[i]);
		}
		return list;
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
		X509Certificate certificate = getX509JavaCertificate(certificateHolder);
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

	
	public static boolean isValid(X509CertificateHolder certificateHolder, Date notBefore, Date notAfter){
		Date certNotBefore = certificateHolder.getNotBefore();
		Date certNotAfter = certificateHolder.getNotAfter();
		boolean before = true;
		boolean after = true;
		if(notBefore!=null)
			before = (certNotBefore!=null) && (notBefore.equals(certNotBefore) || notBefore.after(certNotBefore));
		if(notAfter!=null)
			after = (certNotAfter!=null) && (notAfter.equals(certNotAfter) || notAfter.before(certNotAfter));

		return before && after;
	}
	
	public static boolean isCaKey(X509CertificateHolder cert){
		// check is issuerCertificate is ca certificate
		Extension basicConstraintsExtension = cert.getExtension(X509Extension.basicConstraints);
		BasicConstraints issuerBasicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		if(!issuerBasicConstraints.isCA()) return false;
		
		return KeyUsageUtils.hasAllKeyUsage(cert, KeyUsage.keyCertSign);
	}
	public static boolean isCaKey(Certificate cert){
		X509CertificateHolder certificateHolder = getX509CertificateHolder(cert);
		return isCaKey(certificateHolder);
	}

	public static boolean isSmimeKey(X509CertificateHolder cert){		
		return KeyUsageUtils.hasAnyKeyUsage(cert, KeyUsage.nonRepudiation, KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
	}
	public static boolean isSmimeKey(Certificate cert){
		X509CertificateHolder certificateHolder = getX509CertificateHolder(cert);
		return isSmimeKey(certificateHolder);
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
		
	public static JcaX509ExtensionUtils getJcaX509ExtensionUtils(){
		try {
			return new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}

	public static ContentSigner getContentSigner(PrivateKey privatekey, String algo){
		try {
			return new JcaContentSignerBuilder(algo)
					.setProvider(ProviderUtils.bcProvider).build(privatekey);
		} catch (OperatorCreationException e) {
            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.V3CertificateUtils_read_generalCertificateException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
	}
	
	public static boolean isSigingCertificate(X509CertificateHolder signed,
			X509CertificateHolder signer) {
		// The issuer name of the signed certificate matches the subject name of the signer certificate
		if(signed.getIssuer().equals(signer.getSubject())) return false;
		
		// signer certificate is a ca key
		if(!isCaKey(signer)) return false;
		
		// authority key identifier of signed certificate is not null
		AuthorityKeyIdentifier authorityKeyIdentifier = KeyIdUtils.readAuthorityKeyIdentifier(signed);
		if(authorityKeyIdentifier==null) return false;
		
		// subject identifier of signer certificate is not null
		SubjectKeyIdentifier subjectKeyIdentifier = KeyIdUtils.readSubjectKeyIdentifier(signer);
		
		// both match
		if(Arrays.equals(subjectKeyIdentifier.getKeyIdentifier(), authorityKeyIdentifier.getKeyIdentifier())) return false;
		
		// including serial
		if(!signer.getSerialNumber().equals(authorityKeyIdentifier.getAuthorityCertSerialNumber())) return false;
		
		if(!verify(signed, signer))return false;	
		// then everything is ok
		return true;
	}
	
	private static boolean verify(X509CertificateHolder signed,
			X509CertificateHolder signer) {
		X509Certificate signedJavaCertificate = getX509JavaCertificate(signed);
		X509Certificate signerJavaCertificate = getX509JavaCertificate(signer);
		try {
			signedJavaCertificate.verify(signerJavaCertificate.getPublicKey());
			return true;
		} catch (Exception e) {
			return false;
		}
	}
	
	public static List<List<X509CertificateHolder>> splitCertList(List<X509CertificateHolder> certList){
		LinkedList<X509CertificateHolder> currentList = new LinkedList<X509CertificateHolder>();
		List<List<X509CertificateHolder>> result = new ArrayList<List<X509CertificateHolder>>();;
		for (X509CertificateHolder signed : certList) {
			if (currentList.isEmpty()) {
				currentList.add(signed);continue;
			}
			X509CertificateHolder signer = currentList.getLast();
			if(V3CertificateUtils.isSigingCertificate(signed, signer)){
				currentList.add(signer); continue;
			}
			if(!currentList.isEmpty()){
				result.add(currentList);
				currentList = new LinkedList<X509CertificateHolder>();
			}
		}
		return result;
	}
	
	public static CertStore createCertStore(X509CertificateHolder... certs){
		return createCertStore(Arrays.asList(certs));
	}
	
	public static CertStore createCertStore(List<X509CertificateHolder> certs){
		try {
			if(certs.isEmpty()) return null;
			JcaCertStoreBuilder certStoreBuilder = new JcaCertStoreBuilder().setProvider(ProviderUtils.bcProvider);
			for (X509CertificateHolder signerCertificate : certs) {
				certStoreBuilder.addCertificate(signerCertificate);
			}
			return certStoreBuilder.build();
		} catch (GeneralSecurityException e) {
			return null;
		}
		
	}
	public static List<X509Certificate> convert(Certificate[] certificateChain) {
		X509Certificate[] list = new X509Certificate[certificateChain.length];
		for (int i = 0; i < certificateChain.length; i++) {
			list[i]=(X509Certificate) certificateChain[i];
		}
		return Arrays.asList(list);
	}
}
