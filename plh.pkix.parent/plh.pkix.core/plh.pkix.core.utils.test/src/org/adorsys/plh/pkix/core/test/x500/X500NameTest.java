package org.adorsys.plh.pkix.core.test.x500;

import java.util.List;

import javax.mail.internet.AddressException;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Assert;
import org.junit.Test;


@SuppressWarnings("unused")
public class X500NameTest {

	@Test
	public void testMultipleCN(){
		String mutipleCN="CN=francis,CN=fpo@adorsys.com";
		X500Name x500Name = new X500Name(mutipleCN);
	}

	@Test
	public void testWrongAttr(){
		String mutipleCN="XSC=francis";
		try {
			X500Name x500Name = new X500Name(mutipleCN);
			Assert.fail("IllegalArgumentException expected");
		} catch (IllegalArgumentException e){
			return;
		}
	}
	
	@Test
	public void testUnusualAttr(){
		String emailDN="CN=Francis Pouatcha,EmailAddress=fpo@adorsys.com, C=DE,L=Nürnberg,ST=Bavaria,street=4038 Kingslez Parn Ln\\,Suite 123,postalCode=30096,telephoneNumber=12412341324";	
		X500Name x500Name = new X500Name(emailDN);
	}
	
	@Test
	public void testX500NameBuilder(){
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		X500Name x500Name = x500NameBuilder
			.addRDN(BCStyle.CN, "Francis Pouatcha")
			.addRDN(BCStyle.EmailAddress, "fpo@adorsys.com")
			.addRDN(BCStyle.C, "DE")
			.addRDN(BCStyle.ST, "Bavaria")
			.addRDN(BCStyle.STREET, "Am Rathenauplatz 12-18, Suite 123")
			.addRDN(BCStyle.POSTAL_CODE, "90489")
			.addRDN(BCStyle.TELEPHONE_NUMBER, "+499113023456")
			.addRDN(BCStyle.GENDER, "M").build();
	}
	
	@Test
	public void testParseEmail(){
		List<String> parseEmailAddresses = X500NameHelper.parseEmailAddress("Francis Pouatcha<fpo@adorsys.com>");
		Assert.assertEquals("fpo@adorsys.com", parseEmailAddresses.iterator().next());
	}
}
