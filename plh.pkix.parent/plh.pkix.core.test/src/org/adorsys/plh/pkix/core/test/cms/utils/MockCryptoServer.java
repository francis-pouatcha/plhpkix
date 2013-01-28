package org.adorsys.plh.pkix.core.test.cms.utils;

import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class MockCryptoServer {
	
	private static final CertificateStore certificateStore = new CertificateStore();
	private static final PrivateKeyHolder privateKeyHolder = new PrivateKeyHolder();
	
	static {
		new KeyPairBuilder()
			.withEndEntityName(PlhCMPSystem.getServerName())
			.withPrivateKeyHolder(privateKeyHolder)
			.withCertificateStore(certificateStore)
			.build0();
	}
	
	/**
	 * The certificate database. The Key is the combination of the unique identifier of 
	 * the subject and the unique identifier of the issuer.
	 */
	private static Map<String, X509CertificateHolder> certificateDb = new HashMap<String, X509CertificateHolder>();
	
	public static X509CertificateHolder initialize(X509CertificateHolder tbs){
		X500Name subject = tbs.getSubject();
		String subjectUid = X500NameHelper.getCN(subject);
		if(StringUtils.isBlank(subjectUid)) 
			throw new IllegalArgumentException("expecting a subject unique identifier");
		X500Name issuer = tbs.getIssuer();
		String issuerUid = X500NameHelper.getCN(issuer);
		if(StringUtils.isBlank(issuerUid)) 
			throw new IllegalArgumentException("expecting a issuer unique identifier");
		
		if(!StringUtils.equals(subjectUid, issuerUid))
			throw new IllegalArgumentException("not a self signed certificate");
		String key = key(subjectUid, issuerUid);
		certificateDb.put(key, tbs);
		return null;
		
	}
	
	public static X509CertificateHolder announceCertificate(X509CertificateHolder tbs){
		X500Name subject = tbs.getSubject();
		String subjectUid = X500NameHelper.getCN(subject);
		if(StringUtils.isBlank(subjectUid)) 
			throw new IllegalArgumentException("expecting a subject unique identifier");
		X500Name issuer = tbs.getIssuer();
		String issuerUid = X500NameHelper.getCN(issuer);
		if(StringUtils.isBlank(issuerUid)) 
			throw new IllegalArgumentException("expecting a issuer unique identifier");
		String key = key(subjectUid, issuerUid);
		certificateDb.put(key, tbs);
		return null;
	}
	
	static String combiner = "::";
	public static String key(String subjectUid, String issuerUid) {
		return subjectUid+combiner+issuerUid;
	}
}
