package org.adorsys.plh.pkix.core.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
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
}
