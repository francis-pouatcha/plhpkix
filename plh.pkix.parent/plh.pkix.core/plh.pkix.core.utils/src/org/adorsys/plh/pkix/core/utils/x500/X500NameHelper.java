package org.adorsys.plh.pkix.core.utils.x500;

import java.util.ArrayList;
import java.util.List;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

public class X500NameHelper {

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
	
	public static List<String> parseEmailAddress(String addresses) {
		List<String> result = new ArrayList<String>();
		if(StringUtils.isBlank(addresses)) return result;
		InternetAddress[] internetAddresses;
		try {
			internetAddresses = InternetAddress.parse(addresses);
		} catch (AddressException e) {
			return result;// return empty list
		}
		for (InternetAddress internetAddress : internetAddresses) {
			String em = internetAddress.getAddress().toLowerCase();
			if(!result.contains(em)) result.add(em);
		}
		return result ;
	}

	public static List<String> parseEmailAddress(List<String> addresses) {
		List<String> result = new ArrayList<String>();
		for (String add : addresses) {
			List<String> emailAddresses = parseEmailAddress(add);
			for (String email : emailAddresses) {
				String em = email.toLowerCase();
				if(!result.contains(em))result.add(em);
			}
		}
		return result ;
	}
	
	public static X500Name makeX500Name(String name, String email){
		String emailStrict;
		List<String> parseEmailAddress = X500NameHelper.parseEmailAddress(email);
		if(!parseEmailAddress.isEmpty()){
			emailStrict = parseEmailAddress.iterator().next();
		} else {
			throw new IllegalArgumentException("Email not well formed");
		}
		return new X500NameBuilder(BCStyle.INSTANCE)
			.addRDN(BCStyle.EmailAddress, emailStrict)
			.addRDN(BCStyle.CN, name)
			.build();
	}
	
	public static GeneralNames makeSubjectAlternativeName(X500Name dn, List<String> emails){
		List<GeneralName> generalNames = new ArrayList<GeneralName>();
		if(dn!=null){
			generalNames.add(new GeneralName(dn));
		}
		List<String> parseEmailAddress = parseEmailAddress(emails);
		for (String email : parseEmailAddress) {
			generalNames.add(new GeneralName(GeneralName.rfc822Name, email));
		}
		if(generalNames.isEmpty()) return null;
		GeneralName[] generalNamesArray = generalNames.toArray(new GeneralName[generalNames.size()]);
		return new GeneralNames(generalNamesArray);
	}
	
	private static String readSubjectEmailFromDN(X509CertificateHolder certHolder) {
		X500Name subject = certHolder.getSubject();
		// look for email address field
		return getAttribute(subject, BCStyle.EmailAddress);
	}

	public static List<String> readSubjectEmails(X509CertificateHolder certHolder){
		Extension extension = certHolder.getExtension(X509Extension.subjectAlternativeName);
		List<String> result = new ArrayList<String>();
		if(extension!=null) {
			GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
			GeneralName[] names = generalNames.getNames();
			for (GeneralName generalName : names) {
				if(generalName.getTagNo()==GeneralName.rfc822Name)
					result.add(DERIA5String.getInstance(generalName.getName()).getString());
			}
		}  else {
			String emailAddress = readSubjectEmailFromDN(certHolder);
			if(emailAddress!=null) result.add(emailAddress);
		}
		return result ;
	}
}
