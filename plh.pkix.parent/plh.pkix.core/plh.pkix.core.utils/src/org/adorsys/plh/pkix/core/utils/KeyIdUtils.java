package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.encoders.Hex;

public class KeyIdUtils {
    
    public static byte[] createPublicKeyIdentifierAsByteString(X509CertificateHolder certHldr){
    	SubjectPublicKeyInfo subjectPublicKeyInfo = certHldr.getSubjectPublicKeyInfo();
    	return createPublicKeyIdentifierAsByteString(subjectPublicKeyInfo);
    }
    
    public static String createPublicKeyIdentifierAsString(X509CertificateHolder certHldr){
    	byte[] keyIdentifier = createPublicKeyIdentifierAsByteString(certHldr);
    	return hexEncode(keyIdentifier);
    }
    
    public static SubjectKeyIdentifier createPublicKeyIdentifier(PublicKey subjectPublicKey){
		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return extUtils.createSubjectKeyIdentifier(subjectPublicKey);
    }

    public static SubjectKeyIdentifier createPublicKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo){

		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return extUtils.createSubjectKeyIdentifier(publicKeyInfo);
    }

    public static byte[] createPublicKeyIdentifierAsByteString(PublicKey subjectPublicKey){
    	SubjectKeyIdentifier subjectKeyIdentifier = createPublicKeyIdentifier(subjectPublicKey);
		return subjectKeyIdentifier.getKeyIdentifier();
    }

    public static byte[] createPublicKeyIdentifierAsByteString(SubjectPublicKeyInfo publicKeyInfo){
    	SubjectKeyIdentifier subjectKeyIdentifier = createPublicKeyIdentifier(publicKeyInfo);
    	return subjectKeyIdentifier.getKeyIdentifier();
    }

    public static String createPublicKeyIdentifierAsString(PublicKey subjectPublicKey){
    	return hexEncode(createPublicKeyIdentifierAsByteString(subjectPublicKey));
    }

    public static String createPublicKeyIdentifierAsString(SubjectPublicKeyInfo publicKeyInfo){
    	return hexEncode(createPublicKeyIdentifierAsByteString(publicKeyInfo));
    }
    

    public static byte[] readAuthorityKeyIdentifierAsByteString(X509CertificateHolder certHldr){
        Extension ext = certHldr.getExtension(Extension.authorityKeyIdentifier);

        if (ext == null)
        {
        	throw new IllegalStateException("Expecting a valid authority key id");
        }
        ASN1Encodable value = ext.getParsedValue();
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(value);
        byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
        return keyIdentifier;
    }

    public static String readAuthorityKeyIdentifierAsString(X509CertificateHolder certHldr){
    	byte[] keyIdentifier = readAuthorityKeyIdentifierAsByteString(certHldr);
    	return hexEncode(keyIdentifier);
    }

    public static byte[] readSubjectKeyIdentifierAsByteString(X509CertificateHolder certHldr){
        Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

        if (ext == null)
        {
            return MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo());
        }

        ASN1Encodable value = ext.getParsedValue();
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(value);
    	return subjectKeyIdentifier.getKeyIdentifier();
    }
    
    public static String readSubjectKeyIdentifierAsString(X509CertificateHolder certHldr){
    	byte[] keyIdentifier = readSubjectKeyIdentifierAsByteString(certHldr);
    	return KeyIdUtils.hexEncode(keyIdentifier);
    }
    
    public static String hexEncode(byte[] keyIdentifier){
    	byte[] hexEncoded = Hex.encode(keyIdentifier);
    	String result = new String(hexEncoded).toUpperCase();
    	return result;    	
    }
    
    public static String readSerialNumberAsString(X509CertificateHolder certHldr){
    	BigInteger serialNumber = certHldr.getSerialNumber();
    	return serialNumber.toString(16).toUpperCase();
    }
    
}
