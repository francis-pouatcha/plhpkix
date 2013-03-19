package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1Actions extends ASN1Object {

    private ASN1Sequence content;

    private ASN1Actions(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1Actions getInstance(Object o)
    {
        if (o instanceof ASN1Actions)
        {
            return (ASN1Actions)o;
        }

        if (o != null)
        {
            return new ASN1Actions(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Actions(
        ASN1Action action)
    {
        content = new DERSequence(action);
    }

    public ASN1Actions(
    		ASN1Action[] actions)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < actions.length; i++) {
            v.add(actions[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1Action[] toActionArray()
    {
    	ASN1Action[] result = new ASN1Action[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Action.getInstance(content.getObjectAt(i));
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
