package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.List;

import javax.mail.internet.AddressException;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Computes the key alias for a key entry.
 * 
 * @author francis
 *
 */
public class KeyAliasUtils {
	
	public static final String KeyIdElementSeparator = "_";
	
	/**
	 * Compute the alias needed to store a key and/or certificate including the 
	 * corresponding chain in the keystore.
	 * 
	 * The passed certificate is the one used to directly sing the public key of the
	 * entry. For private key entries, this will generally be the self signed certificate.
	 * 
	 * Certificate provided by ca will have a proper entry.
	 * 
	 * An alias is made out of:
	 *  - The subject key identifier
	 *  - The issuer key identifier
	 *  - The certificates serial number.
	 *  - The owner's email or dn if certificate does not have a valid email.
	 *  
	 *  The purpose of adding an email to the certificae alias if to allow for
	 *  the retrieval of all Entries associated with an email address.
	 *  
	 *  This framework intends to associates a user with many keys like:
	 *  - an email key
	 *  - an archiving key
	 *  - and eventually ca key is the user is an administator in an organization.
	 * 
	 * @param certificateHolder
	 * @return case insensitive concatenation of key identification informations for a key entry.
	 * @throws AddressException 
	 */
	public static String computeKeyAlias(X509CertificateHolder certificateHolder)  throws CertificateException{
		
		// the subjectKeyId
		String subjectKeyIdHex = KeyIdUtils.getSubjectKeyIdentifierAsString(certificateHolder);
		// the authorityKeyId
		String authorityKeyIdHex = KeyIdUtils.getAuthorityKeyIdentifierAsString(certificateHolder);
		
		BigInteger serialNumber = certificateHolder.getSerialNumber();
		
		
		// get the Strict email
		X500Name subjectName = certificateHolder.getSubject();
		String emailAddressStrict = null;
		try {
			emailAddressStrict = X500NameHelper.extractEmailAddress(subjectName);
		} catch (AddressException e) {
			// Do nothing. Simply use common name of dn
			emailAddressStrict = X500NameHelper.getCN1(subjectName);
			if(StringUtils.isBlank(emailAddressStrict)){
				throw new CertificateException("Certificate carries neither a valid email nor a common name");
			}
		}
		
		String result = subjectKeyIdHex + KeyIdElementSeparator + authorityKeyIdHex + KeyIdElementSeparator + makeSeriaNumberFrangment(serialNumber) + KeyIdElementSeparator + emailAddressStrict;
		
		return result.toLowerCase();
	}
	
	public static String makeKeyIdHexFragment(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}
	
	public static String makeSeriaNumberFrangment(BigInteger serialNumber){
		return serialNumber.toString(16);
	}
	
	public static final String selectBySubjectKeyIdentifier(List<String> aliases, byte[] subjectKeyIdentifier){
		String subjectKeyIdHexFragment = makeKeyIdHexFragment(subjectKeyIdentifier);
		for (String alias : aliases) {
			if(StringUtils.startsWithIgnoreCase(alias, subjectKeyIdHexFragment)) return alias;
		}
		return null;
	}

	public static final String selectBySerialNumber(List<String> aliases, BigInteger serialNumber){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		for (String alias : aliases) {
			if(StringUtils.containsIgnoreCase(alias, seriaNumberFrangment)) return alias;
		}
		return null;
	}
}
