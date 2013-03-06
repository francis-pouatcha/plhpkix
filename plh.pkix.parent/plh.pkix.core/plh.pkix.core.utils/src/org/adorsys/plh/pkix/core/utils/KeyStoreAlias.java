package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

public class KeyStoreAlias {

	private static final String KeyIdElementSeparator = "_";
	private static final int PUBLICKEY_ID_POSITION = 0;
	private static final int SUBJECT_KEY_ID_POSITION = 1;
	private static final int ISSUER_KEY_ID_POSITION = 2;
	private static final int SERIAL_NUMBER_POSITION = 3;

	private final String publicKeyIdHex;
	private final String subjectKeyIdHex;
	private final String authorityKeyIdHex;
	private final String serialNumberHex;
	
	private final String alias;
	
	public KeyStoreAlias(X509CertificateHolder subjectCertificateHolder){
		publicKeyIdHex = KeyIdUtils.createPublicKeyIdentifierAsString(subjectCertificateHolder);
		subjectKeyIdHex = KeyIdUtils.readSubjectKeyIdentifierAsString(subjectCertificateHolder);
		authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(subjectCertificateHolder);
		serialNumberHex = KeyIdUtils.readSerialNumberAsString(subjectCertificateHolder);

		StringBuilder sb = new StringBuilder();
		sb.append(publicKeyIdHex).append(KeyIdElementSeparator)
			.append(subjectKeyIdHex).append(KeyIdElementSeparator)
			.append(authorityKeyIdHex).append(KeyIdElementSeparator)
			.append(serialNumberHex);
		alias = sb.toString();
	}
	
	public KeyStoreAlias(String alias){
		this.alias = alias;
		String[] split = alias.split(KeyIdElementSeparator);
		publicKeyIdHex = split[PUBLICKEY_ID_POSITION];
		subjectKeyIdHex = split[SUBJECT_KEY_ID_POSITION];
		authorityKeyIdHex = split[ISSUER_KEY_ID_POSITION];
		serialNumberHex = split[SERIAL_NUMBER_POSITION];
	}

	public KeyStoreAlias(String publicKeyIdHex, String subjectKeyIdHex,
			String authorityKeyIdHex, String serialNumberHex) {
		super();
		this.publicKeyIdHex = publicKeyIdHex;
		this.subjectKeyIdHex = subjectKeyIdHex;
		this.authorityKeyIdHex = authorityKeyIdHex;
		this.serialNumberHex = serialNumberHex;

		StringBuilder sb = new StringBuilder();
		sb.append(publicKeyIdHex).append(KeyIdElementSeparator)
			.append(subjectKeyIdHex).append(KeyIdElementSeparator)
			.append(authorityKeyIdHex).append(KeyIdElementSeparator)
			.append(serialNumberHex);
		alias = sb.toString();
	}

	public String getPublicKeyIdHex() {
		return publicKeyIdHex;
	}

	public String getSubjectKeyIdHex() {
		return subjectKeyIdHex;
	}

	public String getAuthorityKeyIdHex() {
		return authorityKeyIdHex;
	}

	public String getSerialNumberHex() {
		return serialNumberHex;
	}

	public String getAlias() {
		return alias;
	}

	/**
	 * Match any non null field. Null is considered a wild card.
	 * If all fields are null, this is a blanc search.
	 * 
	 * @param a
	 * @return
	 */
	public boolean matchAny(KeyStoreAlias a){
		if(a==null) return true;
		
		if(a.getPublicKeyIdHex()!=null)
			return StringUtils.equalsIgnoreCase(publicKeyIdHex, a.getPublicKeyIdHex());
		
		if(a.getSubjectKeyIdHex()!=null)
			return StringUtils.equalsIgnoreCase(subjectKeyIdHex, a.getSubjectKeyIdHex());
		
		if(a.getAuthorityKeyIdHex()!=null)
			return StringUtils.equalsIgnoreCase(authorityKeyIdHex, a.getAuthorityKeyIdHex());
		
		if(a.getSerialNumberHex()!=null)
			return StringUtils.equalsIgnoreCase(serialNumberHex, a.getSerialNumberHex());
		
		// if all field are null return true;
		return true;
	}

	public boolean matchAll(KeyStoreAlias a){
		if(a==null) return false;
		
		if(a.getPublicKeyIdHex()!=null)
			if(!StringUtils.equalsIgnoreCase(publicKeyIdHex, a.getPublicKeyIdHex()))
				return false;
		
		if(a.getSubjectKeyIdHex()!=null)
			if(!StringUtils.equalsIgnoreCase(subjectKeyIdHex, a.getSubjectKeyIdHex()))
				return false;
		
		if(a.getAuthorityKeyIdHex()!=null)
			if(!StringUtils.equalsIgnoreCase(authorityKeyIdHex, a.getAuthorityKeyIdHex()))
				return false;
		
		if(a.getSerialNumberHex()!=null)
			if(!StringUtils.equalsIgnoreCase(serialNumberHex, a.getSerialNumberHex()))
				return false;
		
		// if all field are null return true;
		return true;
	}
	
	public static String makeKeyIdHexFragment(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}
	
	public static String makeSeriaNumberFrangment(BigInteger serialNumber){
		return serialNumber.toString(16);
	}
	
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, X509CertificateHolder certificateHolder){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null));
	}

	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, SubjectPublicKeyInfo subjectPublicKeyInfo){
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null));
	}
	public static final List<KeyStoreAlias> selectByPublicKeyIdentifier(Enumeration<String> aliases, byte[] publicKeyIdentifierBytes){
		String publicKeyIdentifier = KeyIdUtils.hexEncode(publicKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(publicKeyIdentifier, null,null,null));
	}

	public static final List<KeyStoreAlias> selectBySubjectKeyIdentifier(Enumeration<String> aliases, X509CertificateHolder certificateHolder){
		String subjectKeyIdHexFragment = KeyIdUtils.readSubjectKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null, subjectKeyIdHexFragment,null,null));
	}

	public static final List<KeyStoreAlias> selectBySubjectKeyIdentifier(Enumeration<String> aliases, byte[] subjectKeyIdentifierBytes){
		String subjectKeyIdHexFragment = KeyIdUtils.hexEncode(subjectKeyIdentifierBytes);
		return select(aliases, new KeyStoreAlias(null, subjectKeyIdHexFragment,null,null));
	}
	
	public static final List<KeyStoreAlias> selectBySerialNumber(Enumeration<String> aliases, BigInteger serialNumber){
		String seriaNumberFrangment = makeSeriaNumberFrangment(serialNumber);
		return select(aliases, new KeyStoreAlias(null, null,null,seriaNumberFrangment));
	}
	
	public static final List<KeyStoreAlias> selectByIssuerKeyIdentifier(Enumeration<String> aliases, 
			X509CertificateHolder certificateHolder)
	{
		String authorityKeyIdHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certificateHolder);
		return select(aliases, new KeyStoreAlias(null, null,authorityKeyIdHex,null));
	}

	public static final List<KeyStoreAlias> select(Enumeration<String> aliases, 
			KeyStoreAlias model)
	{
		List<KeyStoreAlias> result = new ArrayList<KeyStoreAlias>();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(alias);
			if(keyStoreAlias.matchAll(model)) result.add(keyStoreAlias);
		}
		return result;
	}
	
	public static String makeKEKAlias(byte[] keyIdentifier){
		return KeyIdUtils.hexEncode(keyIdentifier);
	}

	@Override
	public String toString() {
		return "KeyStoreAlias [alias=" + alias + "]";
	}
}
