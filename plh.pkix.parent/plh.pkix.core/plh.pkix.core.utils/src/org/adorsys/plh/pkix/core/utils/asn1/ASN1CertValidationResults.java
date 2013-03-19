package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class ASN1CertValidationResults extends ASN1Object {

    private ASN1Sequence content;

    private ASN1CertValidationResults(ASN1Sequence seq)
    {
        content = seq;
    }

    public static ASN1CertValidationResults getInstance(Object o)
    {
        if (o instanceof ASN1CertValidationResults)
        {
            return (ASN1CertValidationResults)o;
        }

        if (o != null)
        {
            return new ASN1CertValidationResults(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertValidationResults(
        ASN1CertValidationResult validationResult)
    {
        content = new DERSequence(validationResult);
    }

    public ASN1CertValidationResults(
    		ASN1CertValidationResult[] validationResults)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < validationResults.length; i++) {
            v.add(validationResults[i]);
        }
        content = new DERSequence(v);
    }

    public ASN1CertValidationResults(
    		Certificate[] certificates, ASN1OctetString transactionID)
    {
    	this(toAsn1CertValidationResults(certificates, transactionID));
    }
    
    private static ASN1CertValidationResult[] toAsn1CertValidationResults(Certificate[] certificates, ASN1OctetString transactionID){
    	ASN1CertValidationResult[] validationResults = new ASN1CertValidationResult[certificates.length];
    	for (int i = 0; i < certificates.length; i++) {
    		validationResults[i]=new ASN1CertValidationResult(certificates[i], transactionID);
		}
    	return validationResults;
    }

    public ASN1CertValidationResult[] toResultArray()
    {
    	ASN1CertValidationResult[] result = new ASN1CertValidationResult[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1CertValidationResult.getInstance(content.getObjectAt(i));
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
