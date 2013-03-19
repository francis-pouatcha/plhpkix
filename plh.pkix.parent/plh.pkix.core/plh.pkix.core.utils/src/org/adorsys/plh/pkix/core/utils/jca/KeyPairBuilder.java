package org.adorsys.plh.pkix.core.utils.jca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.KeyPairAndCertificateHolder;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Instantiates and stores a key pair and the corresponding self signed
 * certificate. Returns the alias of the key key pair.
 * 
 * @author francis
 * 
 */
public class KeyPairBuilder {

	private static Provider provider = ProviderUtils.bcProvider;
	
	private X500Name endEntityName;
	private KeyStoreWraper keyStoreWraper;
	private GeneralNames subjectAlternativeNames;

	private final BuilderChecker checker = new BuilderChecker(KeyPairBuilder.class);
	public X509CertificateHolder build() {
		checker.checkDirty().checkNull(endEntityName, keyStoreWraper);

		KeyPairAndCertificateHolder caKeyPairHolder = generateSelfSignedCaKeyPair();
		X509Certificate caCertificate = V3CertificateUtils.getX509JavaCertificate(caKeyPairHolder.getSubjectCertificateHolder());
		keyStoreWraper.setPrivateKeyEntry(caKeyPairHolder.getKeyPair().getPrivate(), new Certificate[]{caCertificate});
		
		KeyPairAndCertificateHolder messageKeyPair = generateSelfCertMessageKeyPair(caKeyPairHolder);
		X509Certificate messageCert = V3CertificateUtils.getX509JavaCertificate(messageKeyPair.getSubjectCertificateHolder());
		keyStoreWraper.setPrivateKeyEntry(messageKeyPair.getKeyPair().getPrivate(), new Certificate[]{messageCert,caCertificate});
		
		return messageKeyPair.getSubjectCertificateHolder();
	}

	public KeyPairBuilder withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public KeyPairBuilder withKeyStoreWraper(KeyStoreWraper keyStoreWraper) {
		this.keyStoreWraper = keyStoreWraper;
		return this;
	}

	public KeyPairBuilder withSubjectAlternativeNames(GeneralNames subjectAlternativeNames) {
		this.subjectAlternativeNames = subjectAlternativeNames;
		return this;
	}

	protected KeyPairAndCertificateHolder generateSelfSignedCaKeyPair(){

		// Generate a key pair for the new EndEntity
		KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance("RSA", provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}

		kGen.initialize(512);
		KeyPair keyPair = kGen.generateKeyPair();

		X509CertificateBuilder builder = new X509CertificateBuilder()
			.withCa(true)
			.withNotBefore(DateUtils.addDays(new Date(), -1))
			.withNotAfter(DateUtils.addDays(new Date(), 300))
			.withSubjectDN(endEntityName)
			.withSubjectPublicKey(keyPair.getPublic());
		int[] keyUsages = KeyUsageUtils.getKeyUsageForCertificationAuthotity();
		for (int keyUsage : keyUsages) {
			builder = builder.withKeyUsage(keyUsage);
		}
		if(subjectAlternativeNames!=null)
			builder = builder.withSubjectAltNames(subjectAlternativeNames);
		X509CertificateHolder caCert = builder.build(keyPair.getPrivate());

		return new KeyPairAndCertificateHolder(keyPair, caCert, null);
	}

	protected KeyPairAndCertificateHolder generateSelfCertMessageKeyPair(KeyPairAndCertificateHolder caKeyPair){

		// Generate a key pair for the new EndEntity
		KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance("RSA", provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}

		kGen.initialize(512);
		KeyPair keyPair = kGen.generateKeyPair();

		X509CertificateBuilder builder = new X509CertificateBuilder()
			.withCa(false)
			.withNotBefore(DateUtils.addDays(new Date(), -1))
			.withNotAfter(DateUtils.addDays(new Date(), 300))
			.withSubjectDN(endEntityName)
			.withIssuerCertificate(caKeyPair.getSubjectCertificateHolder())
			.withSubjectPublicKey(keyPair.getPublic());
		
		// key usage
		int[] keyUsages = KeyUsageUtils.getKeyUsageForSMimeKey();
		for (int keyUsage : keyUsages) {
			builder = builder.withKeyUsage(keyUsage);
		}
		// subject names
		if(subjectAlternativeNames!=null){
			builder = builder.withSubjectAltNames(subjectAlternativeNames);
			builder.withSubjectOnlyInAlternativeName(true);
		}
		
		X509CertificateHolder messageCert = builder.build(caKeyPair.getKeyPair().getPrivate());

		return new KeyPairAndCertificateHolder(keyPair, messageCert, Arrays.asList(caKeyPair.getSubjectCertificateHolder()));
	}
	
}
