package org.adorsys.plh.pkix.core.utils.x500;

import java.util.ArrayList;
import java.util.List;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

public class X500NameHelper {

	public static String getAttributeString(X500Name x500Name, ASN1ObjectIdentifier oid){
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
	
	public static X500Name makeX500Name(String name, String email, String subjectUniqueIdentifier){
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
			.addRDN(BCStyle.UNIQUE_IDENTIFIER, subjectUniqueIdentifier)
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

	public static GeneralName makeSubjectAlternativeName(String email){
		List<String> parseEmailAddress = parseEmailAddress(email);
		return new GeneralName(GeneralName.rfc822Name, parseEmailAddress.iterator().next());
	}
	
	private static String readSubjectEmailFromDN(X509CertificateHolder certHolder) {
		X500Name subject = certHolder.getSubject();
		// look for email address field
		return getAttributeString(subject, BCStyle.EmailAddress);
	}

	public static String readEmailFromDN(X500Name dn) {
		if(dn==null) return null;
		// look for email address field
		return getAttributeString(dn, BCStyle.EmailAddress);
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
		} 

		String emailAddress = readSubjectEmailFromDN(certHolder);
		if(emailAddress!=null) result.add(emailAddress);

		return result ;
	}

	public static List<String> readSubjectEmails(CertTemplate certTemplate) {
		List<String> result = new ArrayList<String>();
		Extensions extensions = certTemplate.getExtensions();
		if(extensions!=null){
			Extension extension = extensions.getExtension(X509Extension.subjectAlternativeName);
			if(extension!=null) {
				GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
				GeneralName[] names = generalNames.getNames();
				for (GeneralName generalName : names) {
					if(generalName.getTagNo()==GeneralName.rfc822Name)
						result.add(DERIA5String.getInstance(generalName.getName()).getString());
				}
			}
		}

		String email1 = readEmailFromDN(certTemplate.getSubject());
		if(email1!=null) result.add(email1);

		return result ;
	}	
	
	/**
	 * Read the subject dn either from the subject field if set or from the subject alternative name.
	 * 
	 * @param certificate
	 * @return
	 */
	public static X500Name readSubjectDN(X509CertificateHolder certificate){
		X500Name subject = certificate.getSubject();
		if(subject!=null){
			RDN[] rdNs = subject.getRDNs();
			if(rdNs.length>1) return subject;// not blank
			AttributeTypeAndValue first = rdNs[0].getFirst();
			String string = first.getValue().toString();
			if(StringUtils.isNotBlank(string)) return subject;
		}
		Extension extension = certificate.getExtension(X509Extension.subjectAlternativeName);
		if(extension!=null) {
			GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
			GeneralName[] names = generalNames.getNames();
			for (GeneralName generalName : names) {
				if(generalName.getTagNo()==GeneralName.directoryName)
					return X500Name.getInstance(generalName.getName());
			}
		}		
		return null;
	}

	public static X500Name readSubjectDN(CertTemplate certTemplate) {
		X500Name subject = certTemplate.getSubject();
		if(subject!=null){
			RDN[] rdNs = subject.getRDNs();
			if(rdNs.length>1) return subject;// not blank
			AttributeTypeAndValue first = rdNs[0].getFirst();
			String string = first.getValue().toString();
			if(StringUtils.isNotBlank(string)) return subject;
		}
		Extensions extensions = certTemplate.getExtensions();
		Extension extension = extensions.getExtension(X509Extension.subjectAlternativeName);
		if(extension!=null) {
			GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
			GeneralName[] names = generalNames.getNames();
			for (GeneralName generalName : names) {
				if(generalName.getTagNo()==GeneralName.directoryName)
					return X500Name.getInstance(generalName.getName());
			}
		}		
		return null;
	}

	public static String readSubjectUniqueIdentifier(X509CertificateHolder certificateHolder){
		X500Name subjectDN = readSubjectDN(certificateHolder);
		return readUniqueIdentifier(subjectDN);
	}
	
	public static String readIssuerUniqueIdentifier(X509CertificateHolder certificateHolder){
		X500Name issuerDN = certificateHolder.getIssuer();
		return readUniqueIdentifier(issuerDN);
	}
	
	public static String readUniqueIdentifier(X500Name subjectDN){
		return getAttributeString(subjectDN, BCStyle.UNIQUE_IDENTIFIER);
	}
	
	public static List<String> readIssuerEmails(CertTemplate certTemplate) {
		List<String> result = new ArrayList<String>();
		String email1 = readEmailFromDN(certTemplate.getIssuer());
		if(email1!=null) result.add(email1);
		Extensions extensions = certTemplate.getExtensions();
		if(extensions!=null){
			Extension extension = extensions.getExtension(X509Extension.issuerAlternativeName);
			if(extension!=null) {
				GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
				GeneralName[] names = generalNames.getNames();
				for (GeneralName generalName : names) {
					if(generalName.getTagNo()==GeneralName.rfc822Name)
						result.add(DERIA5String.getInstance(generalName.getName()).getString());
				}
			}
		}
		return result ;
	}	
	
	public static List<String> readIssuerEmails(X509CertificateHolder certHolder) {
		List<String> result = new ArrayList<String>();
		String emailAddress = readSubjectEmailFromDN(certHolder);
		if(emailAddress!=null) result.add(emailAddress);

		Extension extension = certHolder.getExtension(X509Extension.issuerAlternativeName);
		if(extension!=null) {
			GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
			GeneralName[] names = generalNames.getNames();
			for (GeneralName generalName : names) {
				if(generalName.getTagNo()==GeneralName.rfc822Name)
					result.add(DERIA5String.getInstance(generalName.getName()).getString());
			}
		} 
		return result ;
	}	
}
