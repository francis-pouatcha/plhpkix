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

public class IncomingRequest extends ASN1Object {
	
	// Mandatory
	private ASN1Integer certReqId;
	private PKIMessage pkiMessage;
	private DERGeneralizedTime lastRequest;
	
	// Optional
	private DERGeneralizedTime disposed;
	private DERIA5String status;
	private DERGeneralizedTime lastReply;
	private PKIMessage pollRepMessage;
	private PKIMessage responseMessage;
	private PKIMessage pollReqMessage;
	
	private DERGeneralizedTime processing;
	private DERGeneralizedTime processed;

    private IncomingRequest(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        certReqId = ASN1Integer.getInstance(en.nextElement());
        pkiMessage = PKIMessage.getInstance(en.nextElement());
        lastRequest= DERGeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                disposed = DERGeneralizedTime.getInstance(en.nextElement());
                break;
            case 1:
            	status = DERIA5String.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 2:
                lastReply = DERGeneralizedTime.getInstance(en.nextElement());
                break;
            case 3:
            	pollRepMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 4:
            	responseMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 5:
            	pollReqMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
            case 6:
                processing = DERGeneralizedTime.getInstance(en.nextElement());
            case 7:
                processed = DERGeneralizedTime.getInstance(en.nextElement());
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static IncomingRequest getInstance(Object o)
    {
        if (o instanceof IncomingRequest)
        {
            return (IncomingRequest)o;
        }

        if (o != null)
        {
            return new IncomingRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public IncomingRequest(ASN1Integer certReqId,
    		PKIMessage pkiMessage,
    		DERGeneralizedTime received)
    {
    	this.certReqId = certReqId;
        this.pkiMessage = pkiMessage;
        this.lastRequest = received;
    }

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					certReqId			ASN1Integer
     *                  pkiMessage          PKIMessage,
     *                  received        	DERGeneralizedTime,
     *                  disposed  		[0] DERGeneralizedTime OPTIONAL,
     *                  status  		[1] DERIA5String OPTIONAL,
     *                  lastReply       [2] DERGeneralizedTime,
     *                  pollRepMessage  [3] PKIMessage OPTIONAL,
     *                  responseMessage [4] PKIMessage OPTIONAL,
     *                  pollReqMessage  [5] PKIMessage OPTIONAL,
     *                  processing      [6] DERGeneralizedTime OPTIONAL,
     *                  processed       [7] DERGeneralizedTime OPTIONAL,
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certReqId);
        v.add(pkiMessage);
        v.add(lastRequest);

        addOptional(v, 0, disposed);
        addOptional(v, 1, status);
        addOptional(v, 2, lastReply);
        addOptional(v, 3, pollRepMessage);
        addOptional(v, 4, responseMessage);
        addOptional(v, 5, pollReqMessage);
        addOptional(v, 6, processing);
        addOptional(v, 7, processed);

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

	public DERGeneralizedTime getLastRequest() {
		return lastRequest;
	}

	public void setLastRequest(DERGeneralizedTime lastRequest) {
		this.lastRequest = lastRequest;
	}

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	public void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}

	public DERIA5String getStatus() {
		return status;
	}

	public void setStatus(DERIA5String status) {
		this.status = status;
	}

	public DERGeneralizedTime getLastReply() {
		return lastReply;
	}

	public void setLastReply(DERGeneralizedTime lastReply) {
		this.lastReply = lastReply;
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
