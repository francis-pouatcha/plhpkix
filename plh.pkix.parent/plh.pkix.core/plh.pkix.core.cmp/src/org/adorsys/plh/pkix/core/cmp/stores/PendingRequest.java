package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class PendingRequest extends ASN1Object {
	
	// Mandatory
	private ASN1Integer certReqId;
	private PKIMessage pkiMessage;
	
	// Optional
	private DERGeneralizedTime nextPoll;
	private PKIMessage pollRepMessage;
	private PKIMessage pollReqMessage;
	private DERGeneralizedTime disposed;

    private PendingRequest(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certReqId = ASN1Integer.getInstance(en.nextElement());
        pkiMessage = PKIMessage.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                nextPoll = DERGeneralizedTime.getInstance(en.nextElement());
                break;
            case 1:
            	pollRepMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 2:
            	pollReqMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 3:
            	disposed = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static PendingRequest getInstance(Object o)
    {
        if (o instanceof PendingRequest)
        {
            return (PendingRequest)o;
        }

        if (o != null)
        {
            return new PendingRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PendingRequest(ASN1Integer certReqId,
    		PKIMessage pkiMessage,
    		DERGeneralizedTime nextPoll)
    {
    	this.certReqId = certReqId;
        this.pkiMessage = pkiMessage;
        this.nextPoll = nextPoll;
    }
	
    public PendingRequest(ASN1Integer certReqId, PKIMessage pkiMessage,
			DERGeneralizedTime nextPoll, PKIMessage pollRepMessage,
			PKIMessage pollReqMessage, DERGeneralizedTime disposed) {
		super();
		this.certReqId = certReqId;
		this.pkiMessage = pkiMessage;
		this.nextPoll = nextPoll;
		this.pollRepMessage = pollRepMessage;
		this.pollReqMessage = pollReqMessage;
		this.disposed = disposed;
	}

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					certReqId			ASN1Integer
     *                  pkiMessage          PKIMessage,
     *                  nextPoll        [0] DERGeneralizedTime,
     *                  pollRepMessage  [1] PKIMessage OPTIONAL,
     *                  pollReqMessage  [2] PKIMessage OPTIONAL
     *                  disposed   		[3] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certReqId);
        v.add(pkiMessage);

        addOptional(v, 0, nextPoll);
        addOptional(v, 1, pollRepMessage);
        addOptional(v, 2, pollReqMessage);
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

	public ASN1Integer getCertReqId() {
		return certReqId;
	}

	@SuppressWarnings("unused")
	private final void setCertReqId(ASN1Integer certReqId) {
		this.certReqId = certReqId;
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}

	@SuppressWarnings("unused")
	private final void setPkiMessage(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public DERGeneralizedTime getNextPoll() {
		return nextPoll;
	}

	@SuppressWarnings("unused")
	private final void setNextPoll(DERGeneralizedTime nextPoll) {
		this.nextPoll = nextPoll;
	}

	public PKIMessage getPollRepMessage() {
		return pollRepMessage;
	}

	@SuppressWarnings("unused")
	private final void setPollRepMessage(PKIMessage pollRepMessage) {
		this.pollRepMessage = pollRepMessage;
	}

	public PKIMessage getPollReqMessage() {
		return pollReqMessage;
	}

	@SuppressWarnings("unused")
	private final void setPollReqMessage(PKIMessage pollReqMessage) {
		this.pollReqMessage = pollReqMessage;
	}

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	@SuppressWarnings("unused")
	private final void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}
}
