package org.adorsys.plh.pkix.core.utils.jca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.KeyAliasUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.KeyPairAndCertificateHolder;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Instantiates and stores a key pair and the corresponding self signed
 * certificate. Returns the alias of the key key pair.
 * 
 * @author francis
 * 
 */
public class KeyPairBuilder {

	public static final String KEYSTORETYPE_STRING = "PKCS12";	
	private static Provider provider = ProviderUtils.bcProvider;
	
	private X500Name endEntityName;
	private KeyStore keyStore;

	public String build(char[] privateKeyPassword) throws CertificateException, KeyStoreException {
		try {
			validate();
			KeyPairAndCertificateHolder keyPairAndCertificateHolder = generateSelfSignedKeyPair(endEntityName);
			String alias = KeyAliasUtils.computeKeyAlias(keyPairAndCertificateHolder.getSubjectCertificateHolder());
			X509Certificate certificate = V3CertificateUtils.getCertificate(keyPairAndCertificateHolder.getSubjectCertificateHolder(), provider);
			Certificate[] chain = new Certificate[]{certificate};
			keyStore.setKeyEntry(alias, keyPairAndCertificateHolder.getKeyPair().getPrivate(), privateKeyPassword, chain);
			return alias;
		} finally {
			end();
		}
	}

	public KeyPairBuilder withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public KeyPairBuilder withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	private void validate() {
		assert this.endEntityName != null : "Field endEntityName can not be null";
		assert this.keyStore != null : "Field keyStore can not be null";
	}

	private void end() {
		this.endEntityName = null;
		this.keyStore = null;
	}
	
	protected KeyPairAndCertificateHolder generateSelfSignedKeyPair(X500Name x500Name){

		// Generate a key pair for the new EndEntity
		KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance("RSA", provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}

		kGen.initialize(512);
		KeyPair keyPair = kGen.generateKeyPair();

		X509CertificateHolder cert = new X509CertificateBuilder()
			.setCa(true)
			.setNotBefore(DateUtils.addDays(new Date(), -1))
			.setNotAfter(DateUtils.addDays(new Date(), 300))
			.setSubjectDN(x500Name)
			.setSubjectPublicKey(keyPair.getPublic())
			.build(keyPair.getPrivate());

		return new KeyPairAndCertificateHolder(keyPair, cert, null);
	}
	
}
