package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

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

public class OutgoingCertificationRequest extends ASN1Object {
	
	// Mandatory
	private ASN1Integer certReqId;
	private PKIMessage pkiMessage;
	private DERGeneralizedTime sending;
	
	// Optional
	private DERGeneralizedTime sent;
	private DERIA5String status;

    private OutgoingCertificationRequest(ASN1Sequence seq)
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
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static OutgoingCertificationRequest getInstance(Object o)
    {
        if (o instanceof OutgoingCertificationRequest)
        {
            return (OutgoingCertificationRequest)o;
        }

        if (o != null)
        {
            return new OutgoingCertificationRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public OutgoingCertificationRequest(ASN1Integer certReqId,
    		PKIMessage pkiMessage,
    		DERGeneralizedTime sending)
    {
    	this.certReqId = certReqId;
        this.pkiMessage = pkiMessage;
        this.sending = sending;
    }
	
    public OutgoingCertificationRequest(ASN1Integer certReqId, PKIMessage pkiMessage,
			DERGeneralizedTime sending, DERGeneralizedTime sent,
			DERIA5String status) {
		super();
		this.certReqId = certReqId;
		this.pkiMessage = pkiMessage;
		this.sending = sending;
		this.sent = sent;
		this.status = status;
	}

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					certReqId			ASN1Integer
     *                  pkiMessage          PKIMessage,
     *                  sending        		DERGeneralizedTime,
     *                  sent  			[0] DERGeneralizedTime OPTIONAL,
     *                  status  		[1] DERIA5String
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

	public DERGeneralizedTime getSending() {
		return sending;
	}

	@SuppressWarnings("unused")
	private final void setSending(DERGeneralizedTime sending) {
		this.sending = sending;
	}

	public DERGeneralizedTime getSent() {
		return sent;
	}

	@SuppressWarnings("unused")
	private final void setSent(DERGeneralizedTime sent) {
		this.sent = sent;
	}

	public DERIA5String getStatus() {
		return status;
	}

	@SuppressWarnings("unused")
	private final void setStatus(DERIA5String status) {
		this.status = status;
	}
}
