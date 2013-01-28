package org.adorsys.plh.pkix.core.x500;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class X500NameHelper {

	/**
	 * Return the unique identifier used to index this certificate in the system.
	 * 
	 * @param x500Name
	 * @return
	 */
	public static String getCN(X500Name x500Name){
		RDN[] rdns = x500Name.getRDNs(BCStyle.CN);
		for (RDN rdn : rdns) {
			AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
			for (AttributeTypeAndValue attributeTypeAndValue : typesAndValues) {
				return attributeTypeAndValue.getValue().toString();
			}
		}
		return null;
	}
	
	/**
	 * Extract the first email address from the given string.
	 * 
	 * @param addresses
	 * @return
	 * @throws AddressException 
	 */
	public static String parseEmailAddress(String addresses) throws AddressException{
		InternetAddress[] internetAddresses = InternetAddress.parse(addresses);
		for (InternetAddress internetAddress : internetAddresses) {
			return internetAddress.getAddress();
		}
		return null;
	}
	
	public static X500Name makeX500Name(String name, String email){
		String uniqueIde;
		try {
			uniqueIde = X500NameHelper.parseEmailAddress(email);
		} catch (AddressException e) {
			throw new IllegalArgumentException(e);
		}
		return new X500NameBuilder(BCStyle.INSTANCE)
			.addRDN(BCStyle.UnstructuredName, name)
			.addRDN(BCStyle.EmailAddress, email)
			.addRDN(BCStyle.CN, uniqueIde)
			.build();
	}
}
