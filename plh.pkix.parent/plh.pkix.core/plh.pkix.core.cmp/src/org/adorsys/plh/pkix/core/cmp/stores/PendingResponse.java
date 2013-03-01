package org.adorsys.plh.pkix.core.cmp.stores;

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
import org.bouncycastle.asn1.cmp.PKIMessage;

public class PendingResponse extends ASN1Object {
	
	// Mandatory
	private ASN1OctetString transactionID;
	private PKIMessage pkiMessage;
	private DERGeneralizedTime responseTime;
	// Optional
	private DERGeneralizedTime deliveryTime;

    private PendingResponse(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        transactionID = ASN1OctetString.getInstance(en.nextElement());
        pkiMessage = PKIMessage.getInstance(en.nextElement());
        responseTime = DERGeneralizedTime.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	deliveryTime = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static PendingResponse getInstance(Object o)
    {
        if (o instanceof PendingResponse)
        {
            return (PendingResponse)o;
        }

        if (o != null)
        {
            return new PendingResponse(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PendingResponse(ASN1OctetString transactionID,
    		PKIMessage pkiMessage,
    		DERGeneralizedTime responseTime)
    {
    	this.transactionID = transactionID;
        this.pkiMessage = pkiMessage;
        this.responseTime = responseTime;
    }
	
    /**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					transactionID			OCTET STRING
     *                  pkiMessage          	PKIMessage,
     * 					responseTime			DERGeneralizedTime
     *                  deliveryTime   		[0] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(pkiMessage);
        v.add(responseTime);

        addOptional(v, 0, deliveryTime);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	protected PKIMessage getPkiMessage() {
		return pkiMessage;
	}

	protected void setPkiMessage(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public DERGeneralizedTime getResponseTime() {
		return responseTime;
	}

	public void setResponseTime(DERGeneralizedTime responseTime) {
		this.responseTime = responseTime;
	}

	public DERGeneralizedTime getDeliveryTime() {
		return deliveryTime;
	}

	public void setDeliveryTime(DERGeneralizedTime deliveryTime) {
		this.deliveryTime = deliveryTime;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public void setTransactionID(ASN1OctetString transactionID) {
		this.transactionID = transactionID;
	}

}
