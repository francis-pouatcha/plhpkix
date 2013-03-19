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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class ASN1Action extends ASN1Object {

	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	private ASN1OctetString actionID;
	private DERIA5String actionType;
	
	// Optional
	private DERGeneralizedTime scheduled;
	private DERGeneralizedTime resultIn;
	private DERGeneralizedTime resultOut;
	private DERGeneralizedTime disposed;
	
    private ASN1Action(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created = DERGeneralizedTime.getInstance(en.nextElement());
        actionID = ASN1OctetString.getInstance(en.nextElement());
        actionType = DERIA5String.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	scheduled = DERGeneralizedTime.getInstance(tObj, true);
                break;
            case 1:
            	resultIn = DERGeneralizedTime.getInstance(tObj, true);
                break;
            case 2:
            	resultOut = DERGeneralizedTime.getInstance(tObj, true);
                break;
            case 3:
                disposed = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static ASN1Action getInstance(Object o)
    {
        if (o instanceof ASN1Action)
        {
            return (ASN1Action)o;
        }

        if (o != null)
        {
            return new ASN1Action(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Action(ASN1OctetString transactionID, DERGeneralizedTime created,
    		ASN1OctetString actionID, DERIA5String actionType)
    {
    	this.transactionID = transactionID;
        this.created= created;
        this.actionID = actionID;
        this.actionType = actionType;
    }

	/**
     * <pre>
     * ASN1Action ::= SEQUENCE {
     * 					transactionID		ASN1OctetString
     *                  created	 	  		DERGeneralizedTime,
     * 					actionID 			ASN1OctetString,
     * 					actionType 			DERIA5String,
     *                  scheduled  		[0] DERGeneralizedTime OPTIONAL,
     *                  resultIn  		[1] DERGeneralizedTime OPTIONAL,
     *                  resultOut  		[2] DERGeneralizedTime OPTIONAL,
     *                  disposed	 	[3] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(created);

        addOptional(v, 0, scheduled);
        addOptional(v, 1, resultIn);
        addOptional(v, 2, resultOut);
        addOptional(v, 3, disposed);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
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

	public DERGeneralizedTime getScheduled() {
		return scheduled;
	}

	public void setScheduled(DERGeneralizedTime scheduled) {
		this.scheduled = scheduled;
	}

	public DERGeneralizedTime getResultIn() {
		return resultIn;
	}

	public void setResultIn(DERGeneralizedTime resultIn) {
		this.resultIn = resultIn;
	}

	public DERGeneralizedTime getResultOut() {
		return resultOut;
	}

	public void setResultOut(DERGeneralizedTime resultOut) {
		this.resultOut = resultOut;
	}

	public ASN1OctetString getActionID() {
		return actionID;
	}

	public DERIA5String getActionType() {
		return actionType;
	}

}
