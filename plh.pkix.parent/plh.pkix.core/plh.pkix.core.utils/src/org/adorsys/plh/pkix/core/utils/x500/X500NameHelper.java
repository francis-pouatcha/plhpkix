package org.adorsys.plh.pkix.core.utils.x500;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
	public static String getCN1(X500Name x500Name){
		RDN[] rdns = x500Name.getRDNs(BCStyle.CN);
		for (RDN rdn : rdns) {
			AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
			for (AttributeTypeAndValue attributeTypeAndValue : typesAndValues) {
				return attributeTypeAndValue.getValue().toString().toLowerCase();
			}
		}
		return null;
	}

	public static String getAttribute(X500Name x500Name, ASN1ObjectIdentifier oid){
		RDN[] rdns = x500Name.getRDNs(oid);
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
		if(StringUtils.isBlank(addresses)) return null;
		InternetAddress[] internetAddresses = InternetAddress.parse(addresses);
		for (InternetAddress internetAddress : internetAddresses) {
			return internetAddress.getAddress().toLowerCase();
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
	
	public static String extractEmailAddress(X500Name x500Name) throws AddressException{
		// if cn contains email address, use it.
		String email = X500NameHelper.parseEmailAddress(getCN1(x500Name));
		if(email!=null)return email;
		// look for email address field
		email = X500NameHelper.parseEmailAddress(getAttribute(x500Name, BCStyle.EmailAddress));
		if(email!=null) return email;
		throw new AddressException("No Email found in DN: " + x500Name);
	}
}
