package org.adorsys.plh.pkix.core.utils.asn1;

import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class ASN1CertChainValidationResult extends ASN1Object {

	private ASN1OctetString transactionID;
	private ASN1CertValidationResults validationResults;
	private DERGeneralizedTime created;	

    private ASN1CertChainValidationResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        transactionID = ASN1OctetString.getInstance(en.nextElement());
        validationResults = ASN1CertValidationResults.getInstance(en.nextElement());
        created = DERGeneralizedTime.getInstance(en.nextElement());
    }

    public static ASN1CertChainValidationResult getInstance(Object o)
    {
        if (o instanceof ASN1CertChainValidationResult)
        {
            return (ASN1CertChainValidationResult)o;
        }

        if (o != null)
        {
            return new ASN1CertChainValidationResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertChainValidationResult(ASN1OctetString transactionID,
    		ASN1CertValidationResults validationResults)
    {
    	this.transactionID = transactionID;
    	this.validationResults = validationResults;
        this.created= new DERGeneralizedTime(new Date());
    }	

    public ASN1CertChainValidationResult(ASN1OctetString transactionID,
    		Certificate[] certificateChain)
    {
    	this(transactionID, new ASN1CertValidationResults(certificateChain, transactionID));
    }	
    
	/**
     * <pre>
     * ASN1CertChainValidationResult ::= SEQUENCE {
     * 					transactionID		ASN1OctetString,
     *                  validationResults  	ASN1CertValidationResults,
     *                  created	 	  		DERGeneralizedTime
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(validationResults);
        v.add(created);

        return new DERSequence(v);
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public ASN1CertValidationResults getValidationResults() {
		return validationResults;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
}
