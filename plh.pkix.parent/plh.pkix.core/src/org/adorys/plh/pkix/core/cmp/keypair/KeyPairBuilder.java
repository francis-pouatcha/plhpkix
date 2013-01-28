package org.adorys.plh.pkix.core.cmp.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Instantiates and stores a key pair and the corresponding self signed
 * certificate.
 * 
 * @author francis
 * 
 */
public class KeyPairBuilder {

	private X500Name endEntityName;
	private PrivateKeyHolder privateKeyHolder;
	private CertificateStore certificateStore;

	public void build0() {
		try {
			validate();

			Provider provider = PlhCMPSystem.getProvider();

			// Generate a key pair for the new EndEntity
			KeyPairGenerator kGen;
			try {
				kGen = KeyPairGenerator.getInstance("RSA", provider);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}

			kGen.initialize(512);
			KeyPair keyPair = kGen.generateKeyPair();

			X509CertificateHolder cert = V3CertificateUtils
					.makeSelfV3Certificate(keyPair, endEntityName,
							DateUtils.addDays(new Date(), -1),
							DateUtils.addDays(new Date(), 300), provider);

			certificateStore.addCertificate(cert);
			privateKeyHolder.addKeyPair(keyPair.getPrivate(), cert);
		} finally {
			end();
		}
	}

	public KeyPairBuilder withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public KeyPairBuilder withCertificateStore(CertificateStore certificateStore) {
		this.certificateStore = certificateStore;
		return this;
	}

	public KeyPairBuilder withPrivateKeyHolder(PrivateKeyHolder privateKeyHolder) {
		this.privateKeyHolder = privateKeyHolder;
		return this;
	}

	private void validate() {
		assert this.endEntityName != null : "Field endEntityName can not be null";
		assert this.privateKeyHolder != null : "Field privateKeyHolder can not be null";
		assert this.certificateStore != null : "Field certificateStore can not be null";
	}

	private void end() {
		this.endEntityName = null;
		this.privateKeyHolder = null;
		this.certificateStore = null;
	}
}
