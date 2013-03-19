package org.adorsys.plh.pkix.core.utils.asn1;

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

public class ASN1ProcessingResult extends ASN1Object{
	
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	
	// Optional
	private ASN1MessageBundles errors;
	private ASN1MessageBundles notifications;
	private DERGeneralizedTime disposed;
	
    private ASN1ProcessingResult(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

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
            case 2:
                disposed = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1ProcessingResult getInstance(Object o)
    {
        if (o instanceof ASN1ProcessingResult)
        {
            return (ASN1ProcessingResult)o;
        }

        if (o != null)
        {
            return new ASN1ProcessingResult(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1ProcessingResult(ASN1OctetString transactionID, DERGeneralizedTime created)
    {
    	this.transactionID = transactionID;
        this.created= created;
    }

	/**
     * <pre>
     * ASN1ProcessingResult ::= SEQUENCE {
     * 					transactionID		ASN1OctetString
     *                  created	 	  		DERGeneralizedTime,
     *                  notifications  	[0] ASN1MessageBundles OPTIONAL,
     *                  errors  		[1] ASN1MessageBundles OPTIONAL,
     *                  disposed	 	[2] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(created);

        addOptional(v, 0, notifications);
        addOptional(v, 1, errors);
        addOptional(v, 2, disposed);

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

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	public void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
}
