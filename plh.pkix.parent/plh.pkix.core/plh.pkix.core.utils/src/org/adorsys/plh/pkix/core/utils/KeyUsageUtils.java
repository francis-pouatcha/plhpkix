package org.adorsys.plh.pkix.core.utils;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

public class KeyUsageUtils {

	public static int getKeyUsage(Extensions extensions) {
		Extension keyUsageExtension = extensions.getExtension(X509Extension.keyUsage);
		return extractKeyUsage(keyUsageExtension);
	}
	
	public static int getKeyUsage(X509CertificateHolder issuerCertificate) {
		Extension keyUsageExtension = issuerCertificate.getExtension(X509Extension.keyUsage);
		return extractKeyUsage(keyUsageExtension);
	}
	
	private static int extractKeyUsage(Extension keyUsageExtension){
		if(keyUsageExtension!=null){
            DERBitString ku = KeyUsage.getInstance(keyUsageExtension.getParsedValue().toASN1Primitive());
            return ku.getBytes()[0] & 0xff;
		}
		return -1;
	}

	public static final boolean hasAllKeyUsage(X509CertificateHolder holder, int... keyUsageBits){
    	Extension extension = holder.getExtension(X509Extension.keyUsage);
        if (extension != null){
            DERBitString ku = KeyUsage.getInstance(extension.getParsedValue());
            int bits = ku.getBytes()[0] & 0xff;
            // no bit, false
            if(keyUsageBits.length<=0) return false;
            
            // check all bits. Assume true.
            for (int keyUsageBit : keyUsageBits) {
            	if((bits & keyUsageBit) != keyUsageBit) return false;
			}
            return true;
        } else {
        	// no extensions, no key usage, fine
            if(keyUsageBits.length<=0) return true;
            
            // else false
        	return false;
        }
    }

	public static final boolean hasAnyKeyUsage(X509CertificateHolder holder, int... keyUsageBits){
        // no bit, true
        if(keyUsageBits.length<=0) return true;

        Extension extension = holder.getExtension(X509Extension.keyUsage);
        if (extension != null){
            DERBitString ku = KeyUsage.getInstance(extension.getParsedValue());
            int bits = ku.getBytes()[0] & 0xff;
            // check all bits. Assume true.
            for (int keyUsageBit : keyUsageBits) {
            	if((bits & keyUsageBit) == keyUsageBit) return true;
			}
        } 
        // else false
    	return false;
    }
	
	public static final int[] getKeyUsageForSMimeKey(){
		return new int[]{KeyUsage.digitalSignature, KeyUsage.nonRepudiation,KeyUsage.keyEncipherment};
	}

	public static final int[] getKeyUsageForCertificationAuthotity(){
		return new int[]{KeyUsage.keyCertSign};
	}
}
