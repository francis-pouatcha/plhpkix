package org.adorys.plh.pkix.server.cmp.core.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

public class GeneralNameHolder {

	private GeneralName generalName;

	public GeneralNameHolder(GeneralName generalName) {
		super();
		this.generalName = generalName;
	}
	
	public String getUtf8Name(){
		return generalName.getName().toString();
	}
	
	public ASN1Encodable getASN1EncodableName(){
		return generalName.getName();
	}
	
	public X500Name getX500Name(){
		return X500Name.getInstance(generalName.getName());
	}
}
