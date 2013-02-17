package org.adorsys.plh.pkix.core.cmp.utils;

import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x509.Time;


public class OptionalValidityHolder {

    private final Time notBefore;
    private final Time notAfter;
    
    private final OptionalValidity optionalValidity;
	public OptionalValidityHolder(Time notBefore, Time notAfter) {
		this.notBefore = notBefore;
		this.notAfter = notAfter;
        ASN1EncodableVector validity = new ASN1EncodableVector();
		validity.add(new DERTaggedObject(true, 0, this.notBefore));
		validity.add(new DERTaggedObject(true, 1, this.notAfter));
		this.optionalValidity = OptionalValidity.getInstance(new DERSequence(validity));
	}

	public OptionalValidityHolder(OptionalValidity optionalValidity) {
		this.optionalValidity = optionalValidity;
		DERSequence rawValidity = (DERSequence) optionalValidity.toASN1Primitive();
		notBefore = new Time(((DERTaggedObject) rawValidity.getObjectAt(0)).getObject());
		notAfter = new Time(((DERTaggedObject) rawValidity.getObjectAt(1)).getObject());		
	}

	public OptionalValidityHolder(Date notBefore, Date notAfter) {
		this(new Time(notBefore), new Time(notAfter));
	}

	public Time getNotBefore() {
		return notBefore;
	}

	public Time getNotAfter() {
		return notAfter;
	}
	
	public Date getNotBeforeAsDate(){
		if(notBefore==null) return null;
		return notBefore.getDate();
	}
	
	public Date getNotAfterAsDate(){
		if(notAfter==null) return null;
		return notAfter.getDate();
	}
	
	public OptionalValidity getOptionalValidity() {
		return optionalValidity;
	}
}
