package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1CertChainValidationResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertChainValidationResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertChainValidationResults getInstance(Object o)
    {
        if (o instanceof ASN1CertChainValidationResults)
        {
            return (ASN1CertChainValidationResults)o;
        }

        if (o != null)
        {
            return new ASN1CertChainValidationResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertChainValidationResults(
        ASN1CertChainValidationResult validationResult)
    {
        content = new DERSequence(validationResult);
    }

    public ASN1CertChainValidationResults(
    		ASN1CertChainValidationResult[] validationResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < validationResults.length; i++) {
            v.add(validationResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertChainValidationResult[] toResultArray()
    {
    	ASN1CertChainValidationResult[] result = new ASN1CertChainValidationResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertChainValidationResult.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * ASN1CertChainValidationResults ::= SEQUENCE SIZE (1..MAX) OF ASN1CertChainValidationResult
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
