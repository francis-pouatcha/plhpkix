package org.adorys.plh.pkix.core.cmp.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Instantiates and stores a key pair and the corresponding self signed certificate.
 * 
 * @author francis
 *
 */
public class KeyPairBuilder {

	private X500Name endEntityName;

    public void build() throws NoSuchAlgorithmException{
    	
    	validate();
    	
		Provider provider = PlhCMPSystem.getProvider();
		
		// Generate a key pair for the new EndEntity
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", provider);
        kGen.initialize(512);
        KeyPair keyPair = kGen.generateKeyPair();

        X509CertificateHolder cert = V3CertificateUtils.makeSelfV3Certificate(
        		keyPair, endEntityName.toString(), keyPair, endEntityName.toString(), provider);

        CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
        certificateStore.addCertificate(cert);
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder.getInstance(endEntityName);
        privateKeyHolder.addKeyPair(keyPair.getPrivate(), cert);
        
        end();
	}

	public KeyPairBuilder withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	private void  validate() {
		assert this.endEntityName!=null: "Field endEntityName can not be null";
	}

	private void  end() {
		this.endEntityName = null;
	}
}
