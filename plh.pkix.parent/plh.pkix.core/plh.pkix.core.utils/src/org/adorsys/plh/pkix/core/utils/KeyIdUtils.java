package org.adorsys.plh.pkix.core.utils;

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
    
    public static byte[] getSubjectKeyIdentifierAsByteString(X509CertificateHolder certHldr){
        Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

        if (ext == null)
        {
            return MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo());
        }

        ASN1Encodable value = ext.getParsedValue();
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(value);
    	return subjectKeyIdentifier.getKeyIdentifier();
    }
    
    public static String getSubjectKeyIdentifierAsString(X509CertificateHolder certHldr){
    	byte[] keyIdentifier = getSubjectKeyIdentifierAsByteString(certHldr);
    	return hexEncode(keyIdentifier);
    }

    public static byte[] getAuthorityKeyIdentifierAsByteString(X509CertificateHolder certHldr){
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

    public static String getAuthorityKeyIdentifierAsString(X509CertificateHolder certHldr){
    	byte[] keyIdentifier = getAuthorityKeyIdentifierAsByteString(certHldr);
    	return hexEncode(keyIdentifier);
    }
    
    public static String hexEncode(byte[] keyIdentifier){
    	byte[] hexEncoded = Hex.encode(keyIdentifier);
    	String result = new String(hexEncoded);
    	return result;    	
    }
    
    public static SubjectKeyIdentifier getSubjectKeyIdentifier(PublicKey subjectPublicKey){

		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return extUtils.createSubjectKeyIdentifier(subjectPublicKey);
    }

    public static SubjectKeyIdentifier getSubjectKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo){

		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return extUtils.createSubjectKeyIdentifier(publicKeyInfo);
    }

    public static byte[] getSubjectKeyIdentifierAsByteString(PublicKey subjectPublicKey){
    	SubjectKeyIdentifier subjectKeyIdentifier = getSubjectKeyIdentifier(subjectPublicKey);
		return subjectKeyIdentifier.getKeyIdentifier();
    }

    public static byte[] getSubjectKeyIdentifierAsByteString(SubjectPublicKeyInfo publicKeyInfo){
    	SubjectKeyIdentifier subjectKeyIdentifier = getSubjectKeyIdentifier(publicKeyInfo);
    	return subjectKeyIdentifier.getKeyIdentifier();
    }

    public static String getSubjectKeyIdentifierAsString(PublicKey subjectPublicKey){
    	return hexEncode(getSubjectKeyIdentifierAsByteString(subjectPublicKey));
    }

    public static String getSubjectKeyIdentifierAsString(SubjectPublicKeyInfo publicKeyInfo){
    	return hexEncode(getSubjectKeyIdentifierAsByteString(publicKeyInfo));
    }
}
