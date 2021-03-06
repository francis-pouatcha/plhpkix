package org.adorsys.plh.pkix.core.utils;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

public class MSOutlookKeyIdCalculator
{
    public static byte[] calculateKeyId(SubjectPublicKeyInfo info)
    {
        Digest dig = new SHA1Digest();    // TODO: include definition of SHA-1 here
        byte[] hash = new byte[dig.getDigestSize()];
        byte[] spkiEnc = new byte[0];
        try
        {
            spkiEnc = info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return new byte[0];
        }

        // try the outlook 2010 calculation
        dig.update(spkiEnc, 0, spkiEnc.length);

        dig.doFinal(hash, 0);

        return hash;
    }
}
