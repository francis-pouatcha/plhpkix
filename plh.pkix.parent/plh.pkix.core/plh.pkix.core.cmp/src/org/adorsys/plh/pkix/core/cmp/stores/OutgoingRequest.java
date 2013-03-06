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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class OutgoingRequest extends ASN1Object {
	
	public static final String STATUS_OK = "OK";
	public static final String STATUS_ERROR = "ERROR: ";
	
	// Mandatory
	private ASN1Integer certReqId;
	private PKIMessage pkiMessage;
	private DERGeneralizedTime sending;
	
	// Optional
	private DERGeneralizedTime sent;
	private DERIA5String status;
	
	// Optional
	private DERGeneralizedTime nextPoll;
	private PKIMessage pollRepMessage;
	private PKIMessage responseMessage;
	private PKIMessage pollReqMessage;
	private DERGeneralizedTime disposed;
	
	private DERGeneralizedTime processing;
	private DERGeneralizedTime processed;

    private OutgoingRequest(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certReqId = ASN1Integer.getInstance(en.nextElement());
        pkiMessage = PKIMessage.getInstance(en.nextElement());
        sending= DERGeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                sent = DERGeneralizedTime.getInstance(en.nextElement());
                break;
            case 1:
            	status = DERIA5String.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 2:
                nextPoll = DERGeneralizedTime.getInstance(en.nextElement());
                break;
            case 3:
            	pollRepMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 4:
            	responseMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 5:
            	pollReqMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 6:
            	disposed = DERGeneralizedTime.getInstance(tObj, true);
            case 7:
                processing = DERGeneralizedTime.getInstance(en.nextElement());
            case 8:
                processed = DERGeneralizedTime.getInstance(en.nextElement());
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static OutgoingRequest getInstance(Object o)
    {
        if (o instanceof OutgoingRequest)
        {
            return (OutgoingRequest)o;
        }

        if (o != null)
        {
            return new OutgoingRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public OutgoingRequest(ASN1Integer certReqId,
    		PKIMessage pkiMessage,
    		DERGeneralizedTime sending)
    {
    	this.certReqId = certReqId;
        this.pkiMessage = pkiMessage;
        this.sending = sending;
    }

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					certReqId			ASN1Integer
     *                  pkiMessage          PKIMessage,
     *                  sending        		DERGeneralizedTime,
     *                  sent  			[0] DERGeneralizedTime OPTIONAL,
     *                  status  		[1] DERIA5String OPTIONAL,
     *                  nextPoll        [2] DERGeneralizedTime,
     *                  pollRepMessage  [3] PKIMessage OPTIONAL,
     *                  responseMessage [3] PKIMessage OPTIONAL,
     *                  pollReqMessage  [5] PKIMessage OPTIONAL
     *                  disposed   		[6] DERGeneralizedTime OPTIONAL.
     *                  processing      [7] DERGeneralizedTime OPTIONAL,
     *                  processed       [8] DERGeneralizedTime OPTIONAL,
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certReqId);
        v.add(pkiMessage);
        v.add(sending);

        addOptional(v, 0, sent);
        addOptional(v, 1, status);
        addOptional(v, 2, nextPoll);
        addOptional(v, 3, pollRepMessage);
        addOptional(v, 4, responseMessage);
        addOptional(v, 5, pollReqMessage);
        addOptional(v, 6, disposed);
        addOptional(v, 7, processing);
        addOptional(v, 8, processed);

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

	public void setCertReqId(ASN1Integer certReqId) {
		this.certReqId = certReqId;
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}

	public void setPkiMessage(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public DERGeneralizedTime getSending() {
		return sending;
	}

	public void setSending(DERGeneralizedTime sending) {
		this.sending = sending;
	}

	public DERGeneralizedTime getSent() {
		return sent;
	}

	public void setSent(DERGeneralizedTime sent) {
		this.sent = sent;
	}

	public DERIA5String getStatus() {
		return status;
	}

	public void setStatus(DERIA5String status) {
		this.status = status;
	}

	public DERGeneralizedTime getNextPoll() {
		return nextPoll;
	}

	public void setNextPoll(DERGeneralizedTime nextPoll) {
		this.nextPoll = nextPoll;
	}

	public PKIMessage getPollRepMessage() {
		return pollRepMessage;
	}

	public void setPollRepMessage(PKIMessage pollRepMessage) {
		this.pollRepMessage = pollRepMessage;
	}

	public PKIMessage getResponseMessage() {
		return responseMessage;
	}

	public void setResponseMessage(PKIMessage responseMessage) {
		this.responseMessage = responseMessage;
	}

	public PKIMessage getPollReqMessage() {
		return pollReqMessage;
	}

	public void setPollReqMessage(PKIMessage pollReqMessage) {
		this.pollReqMessage = pollReqMessage;
	}

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	public void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}

	public DERGeneralizedTime getProcessing() {
		return processing;
	}

	public void setProcessing(DERGeneralizedTime processing) {
		this.processing = processing;
	}

	public DERGeneralizedTime getProcessed() {
		return processed;
	}

	public void setProcessed(DERGeneralizedTime processed) {
		this.processed = processed;
	}
}
