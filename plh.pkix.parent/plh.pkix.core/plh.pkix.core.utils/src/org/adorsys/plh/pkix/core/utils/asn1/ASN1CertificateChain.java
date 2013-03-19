package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class ASN1CertificateChain extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertificateChain(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertificateChain getInstance(Object o)
    {
        if (o instanceof ASN1CertificateChain)
        {
            return (ASN1CertificateChain)o;
        }

        if (o != null)
        {
            return new ASN1CertificateChain(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertificateChain(
        Certificate crt)
    {
        content = new DERSequence(crt);
    }

    public ASN1CertificateChain(
    		Certificate[] crts)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < crts.length; i++) {
            v.add(crts[i]);
        }
        content = new DERSequence(v);
    }

    public Certificate[] toCertArray()
    {
    	Certificate[] result = new Certificate[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = Certificate.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertificateChain ::= SEQUENCE SIZE (1..MAX) OF Certificate
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }

	@SuppressWarnings("unused")
	private final ASN1Sequence getContent() {
		return content;
	}
	@SuppressWarnings("unused")
	private final void setContent(ASN1Sequence content) {
		this.content = content;
	}
}
