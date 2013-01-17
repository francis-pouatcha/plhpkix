package org.adorys.plh.pkix.core.cmp.utils;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;

public class KeyIdUtils {
    
    public static byte[] getSubjectKeyIdentifierAsByteString(X509CertificateHolder certHldr){
        Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

        if (ext == null)
        {
            return MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo());
        }

        return ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();
    	
    }

    public static ASN1OctetString getSubjectKeyIdentifierAsOctetString(X509CertificateHolder certHldr){
        Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

        if (ext == null)
        {
        	byte[] keyId = MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo());
            return new DEROctetString(keyId);
        }

        return ASN1OctetString.getInstance(ext.getParsedValue());
    	
    }
}
