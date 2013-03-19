package org.adorsys.plh.pkix.core.utils.asn1;

import org.junit.Test;

public class ASN1ProcessingStatusTest {

	@SuppressWarnings("unused")
	@Test
	public void test() {
		ASN1ProcessingStatus status = new ASN1ProcessingStatus(ASN1ProcessingStatus.response_sent);
		String string = status.getString();
		String string4 = status.toString();
		int intValue2 = status.intValue();
		ASN1ProcessingStatus status2=new ASN1ProcessingStatus(ASN1ProcessingStatus.request_sent | ASN1ProcessingStatus.disposed);
		String string2 = status2.getString();
		String string3 = status2.toString();
		int intValue = status2.intValue();
		ASN1ProcessingStatus status3=new ASN1ProcessingStatus(ASN1ProcessingStatus.request_sent | ASN1ProcessingStatus.unknown);
		String string5 = status3.getString();
		String string6 = status3.toString();
		int intValue3 = status3.intValue();
		
//		new ASN1ProcessingStatus(new DERBMPString(string));
	}

}
