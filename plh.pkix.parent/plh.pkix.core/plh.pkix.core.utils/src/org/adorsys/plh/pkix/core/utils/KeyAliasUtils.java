package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.mail.internet.AddressException;

import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Computes the key alias for a key entry.
 * 
 * @author francis
 *
 */
public class KeyAliasUtils {
	
	private static final String KeyIdElementSeparator = "_";
	private static final int SUBJECT_KEY_ID_POSITION = 0;
	private static final int ISSUER_KEY_ID_POSITION = 1;
	private static final int SERIAL_NUMBER_POSITION = 2;
	private static final int EMAIL_ADDRESS_POSITION = 3;
	
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
	public static String computeKeyAlias(X509CertificateHolder certificateHolder)  {
		
		// the subjectKeyId
		String subjectKeyIdHex = KeyIdUtils.getSubjectKeyIdentifierAsString(certificateHolder);
		// the authorityKeyId
		String authorityKeyIdHex = KeyIdUtils.getAuthorityKeyIdentifierAsString(certificateHolder);
		
		BigInteger serialNumber = certificateHolder.getSerialNumber();
		
		
		// get the Strict email
		X500Name subjectName = certificateHolder.getSubject();
		String emailAddressStrict = extractCNAsEmailWithFallback(subjectName);

		String result = subjectKeyIdHex + KeyIdElementSeparator + authorityKeyIdHex + KeyIdElementSeparator + makeSeriaNumberFrangment(serialNumber) + KeyIdElementSeparator + emailAddressStrict;
		
		return result.toLowerCase();
	}
	
	private static String extractCNAsEmailWithFallback(X500Name subjectName){
		String emailAddressStrict = null;
		try {
			emailAddressStrict = X500NameHelper.extractEmailAddress(subjectName);
		} catch (AddressException e) {
			// Do nothing. Simply use common name of dn
			emailAddressStrict = X500NameHelper.getCN1(subjectName);
			if(StringUtils.isBlank(emailAddressStrict)){
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.KeyAliasUtils_cn_addressException,
	                    new Object[] { e.getMessage(), e , e.getClass().getName()});
	            throw new PlhUncheckedException(msg, e);
			}
		}
		return emailAddressStrict;
	}
	
	public static String makeKeyIdHexFragment(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}
	
	public static String makeSeriaNumberFrangment(BigInteger serialNumber){
		return serialNumber.toString(16);
	}
	
	public static final List<String> selectBySubjectKeyIdentifier(Enumeration<String> aliases, byte[] subjectKeyIdentifier){
		String subjectKeyIdHexFragment = makeKeyIdHexFragment(subjectKeyIdentifier);
		return select(aliases, subjectKeyIdHexFragment, SUBJECT_KEY_ID_POSITION);
	}

	public static final List<String> selectBySerialNumber(Enumeration<String> aliases, BigInteger serialNumber){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, seriaNumberFrangment, SERIAL_NUMBER_POSITION);
	}
	
	public static final List<String> selectByIssuerKeyIdentifier(Enumeration<String> aliases, 
			X509CertificateHolder certificateHolder)
	{
		String authorityKeyIdHex = KeyIdUtils.getAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, authorityKeyIdHex, ISSUER_KEY_ID_POSITION);
	}

	public static final List<String> selectBySubjectName(Enumeration<String> aliases, 
			X500Name subjectName)
	{
		String subjectEmail = extractCNAsEmailWithFallback(subjectName);
		return select(aliases, subjectEmail, EMAIL_ADDRESS_POSITION);
	}
	

	public static final List<String> select(Enumeration<String> aliases, 
			String fragment, int pos)
	{
		List<String> result = new ArrayList<String>();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			if(StringUtils.containsIgnoreCase(alias, fragment)) {
				String[] split = alias.split(KeyIdElementSeparator);
				if(split.length<3) continue;
				if(fragment.equalsIgnoreCase(split[pos])) result.add(alias);
			}
		}
		return result;
	}
	
}
