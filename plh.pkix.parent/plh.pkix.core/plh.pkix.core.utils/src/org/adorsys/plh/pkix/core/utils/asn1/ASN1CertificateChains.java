package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertificateChains extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertificateChains(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertificateChains getInstance(Object o)
    {
        if (o instanceof ASN1CertificateChains)
        {
            return (ASN1CertificateChains)o;
        }

        if (o != null)
        {
            return new ASN1CertificateChains(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertificateChains(
        ASN1CertificateChain chain)
    {
        content = new DERSequence(chain);
    }

    public ASN1CertificateChains(
    		ASN1CertificateChain[] chains)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < chains.length; i++) {
            v.add(chains[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertificateChain[] toCertArray()
    {
    	ASN1CertificateChain[] result = new ASN1CertificateChain[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertificateChain.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertificateChains ::= SEQUENCE SIZE (1..MAX) OF CertificateChain
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
