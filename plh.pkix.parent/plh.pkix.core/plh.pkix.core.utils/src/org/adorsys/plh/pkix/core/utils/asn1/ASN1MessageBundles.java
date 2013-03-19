package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1MessageBundles extends ASN1Object {

    private ASN1Sequence content;

    private ASN1MessageBundles(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1MessageBundles getInstance(Object o)
    {
        if (o instanceof ASN1MessageBundles)
        {
            return (ASN1MessageBundles)o;
        }

        if (o != null)
        {
            return new ASN1MessageBundles(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1MessageBundles(
    		ASN1MessageBundle bundle)
    {
        content = new DERSequence(bundle);
    }

    public ASN1MessageBundles(
    		ASN1MessageBundle[] bundles)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < bundles.length; i++) {
            v.add(bundles[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1MessageBundle[] toCertArray()
    {
    	ASN1MessageBundle[] result = new ASN1MessageBundle[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1MessageBundle.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * ASN1MessageBundles ::= SEQUENCE SIZE (1..MAX) OF ASN1MessageBundle
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
