package org.adorsys.plh.pkix.core.utils.asn1;

import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;

public class ASN1CertValidationResult extends ASN1Object {

	private Certificate certificate;
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	
	// Optional
	private ASN1MessageBundles errors;
	private ASN1MessageBundles notifications;
	

    private ASN1CertValidationResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certificate = Certificate.getInstance(en.nextElement());
        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created = DERGeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                notifications= ASN1MessageBundles.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 1:
                errors = ASN1MessageBundles.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1CertValidationResult getInstance(Object o)
    {
        if (o instanceof ASN1CertValidationResult)
        {
            return (ASN1CertValidationResult)o;
        }

        if (o != null)
        {
            return new ASN1CertValidationResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1CertValidationResult(Certificate certificate,
    		ASN1OctetString transactionID)
    {
    	this.certificate = certificate;
    	this.transactionID = transactionID;
        this.created= new DERGeneralizedTime(new Date());
    }

	/**
     * <pre>
     * ASN1CertValidationResult ::= SEQUENCE {
     * 					certificate			Certificate
     * 					transactionID		ASN1OctetString
     *                  created	 	  		DERGeneralizedTime,
     *                  notifications  	[0] ASN1MessageBundles OPTIONAL,
     *                  errors  		[1] ASN1MessageBundles OPTIONAL,
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certificate);
        v.add(transactionID);
        v.add(created);

        addOptional(v, 0, notifications);
        addOptional(v, 1, errors);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1MessageBundles getErrors() {
		return errors;
	}

	public void setErrors(ASN1MessageBundles errors) {
		this.errors = errors;
	}

	public ASN1MessageBundles getNotifications() {
		return notifications;
	}

	public void setNotifications(ASN1MessageBundles notifications) {
		this.notifications = notifications;
	}

	public Certificate getCertificate() {
		return certificate;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
}
