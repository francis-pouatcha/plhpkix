package org.adorsys.plh.pkix.core.utils.asn1;

import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.i18n.MessageBundle;

public class ASN1MessageBundle extends ASN1Object {

	private DERIA5String id;
	private DERUTF8String title;
	private DERUTF8String text;
	
	private DERGeneralizedTime created;

	private ASN1MessageBundle(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();
        
        id=DERIA5String.getInstance(en.nextElement());
        title = DERUTF8String.getInstance(en.nextElement());
        text = DERUTF8String.getInstance(en.nextElement());
        created= DERGeneralizedTime.getInstance(en.nextElement());
    }

    public static ASN1MessageBundle getInstance(Object o)
    {
        if (o instanceof ASN1MessageBundle)
        {
            return (ASN1MessageBundle)o;
        }

        if (o != null)
        {
            return new ASN1MessageBundle(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1MessageBundle(
    		DERIA5String id,
    		DERUTF8String title,
    		DERUTF8String text)
    {
    	this.id=id;
        this.title = title;
        this.text = text;
        this.created=new DERGeneralizedTime(new Date());
    }
    
    public ASN1MessageBundle(MessageBundle messageBundle, Locale loc){
    	this.id = new DERIA5String(messageBundle.getId());
    	this.title = new DERUTF8String(messageBundle.getTitle(loc));
    	this.text = new DERUTF8String(messageBundle.getText(loc));
        this.created=new DERGeneralizedTime(new Date());
    }

	/**
     * <pre>
     * ASN1MessageBundle ::= SEQUENCE {
     * 					id			DERIAS5String,
     * 					title		DERUTF8String,
     *                  text        DERUTF8String,
     *                  created     DERGeneralizedTime
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(id);
        v.add(title);
        v.add(text);
        v.add(created);
        return new DERSequence(v);
	}

	public DERIA5String getId() {
		return id;
	}

	public DERUTF8String getTitle() {
		return title;
	}

	public DERUTF8String getText() {
		return text;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
}
