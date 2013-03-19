package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ASN1ProcessingResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1ProcessingResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1ProcessingResults getInstance(Object o)
    {
        if (o instanceof ASN1ProcessingResults)
        {
            return (ASN1ProcessingResults)o;
        }

        if (o != null)
        {
            return new ASN1ProcessingResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1ProcessingResults(
        ASN1ProcessingResult processingResult)
    {
        content = new DERSequence(processingResult);
    }

    public ASN1ProcessingResults(
    		ASN1ProcessingResult[] validationResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < validationResults.length; i++) {
            v.add(validationResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1ProcessingResult[] toResultArray()
    {
    	ASN1ProcessingResult[] result = new ASN1ProcessingResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1ProcessingResult.getInstance(content.getObjectAt(i));
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
