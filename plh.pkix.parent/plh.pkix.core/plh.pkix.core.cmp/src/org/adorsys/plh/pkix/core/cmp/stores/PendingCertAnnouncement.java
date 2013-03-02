package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.Enumeration;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
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

public class PendingCertAnnouncement extends ASN1Object {
	
	// Mandatory
	private ASN1Integer serial;
	private CertificateChain certificateChain;
	private DERGeneralizedTime announcementTime;
	// Optional
	private DERGeneralizedTime announcedtTime;

    private PendingCertAnnouncement(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        serial = ASN1Integer.getInstance(en.nextElement());
        certificateChain = CertificateChain.getInstance(en.nextElement());
        announcementTime = DERGeneralizedTime.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	announcedtTime = DERGeneralizedTime.getInstance(tObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static PendingCertAnnouncement getInstance(Object o)
    {
        if (o instanceof PendingCertAnnouncement)
        {
            return (PendingCertAnnouncement)o;
        }

        if (o != null)
        {
            return new PendingCertAnnouncement(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PendingCertAnnouncement(ASN1Integer serial,
    		CertificateChain certificateChain,
    		DERGeneralizedTime announcementTime)
    {
    	this.serial = serial;
        this.certificateChain = certificateChain;
        this.announcementTime = announcementTime;
    }
    public PendingCertAnnouncement(ASN1Integer serial,
    		CertificateChain certificateChain,
    		DERGeneralizedTime announcementTime, DERGeneralizedTime announcedTime)
    {
    	this(serial, certificateChain, announcementTime);
    	this.announcedtTime = announcedTime;
    }
	
    /**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					serial				ASN1Integer
     *                  certificateChain    CertificateChain,
     *                  announcementTime    DERGeneralizedTime,
     *                  announcedtTime  [0] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(serial);
        v.add(certificateChain);
        v.add(announcementTime);

        addOptional(v, 0, announcedtTime);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1Integer getSerial() {
		return serial;
	}

	public CertificateChain getCertificateChain() {
		return certificateChain;
	}

	public DERGeneralizedTime getAnnouncementTime() {
		return announcementTime;
	}

	public DERGeneralizedTime getAnnouncedtTime() {
		return announcedtTime;
	}

	@SuppressWarnings("unused")
	private final void setSerial(ASN1Integer serial) {
		this.serial = serial;
	}
	@SuppressWarnings("unused")
	private final void setCertificateChain(CertificateChain certificateChain) {
		this.certificateChain = certificateChain;
	}
	@SuppressWarnings("unused")
	private final void setAnnouncementTime(DERGeneralizedTime announcementTime) {
		this.announcementTime = announcementTime;
	}
	@SuppressWarnings("unused")
	private final void setAnnouncedtTime(DERGeneralizedTime announcedtTime) {
		this.announcedtTime = announcedtTime;
	}
}
