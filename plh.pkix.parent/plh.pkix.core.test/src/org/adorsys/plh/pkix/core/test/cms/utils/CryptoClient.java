package org.adorsys.plh.pkix.core.test.cms.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.adorsys.plh.pkix.core.cms.utils.SignEncryptUtils;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.bouncycastle.asn1.x500.X500Name;

public class CryptoClient {

	private final X500Name nameX500;
	
	private final PrivateKeyHolder privateKeyHolder;
	
	private final CertificateStore certificateStore;

	public CryptoClient(X500Name nameX500, PrivateKeyHolder privateKeyHolder, CertificateStore certificateStore) {
		this.nameX500 = nameX500;
		this.privateKeyHolder = privateKeyHolder;
		this.certificateStore = certificateStore;
		new KeyPairBuilder()
			.withEndEntityName(nameX500)
			.withPrivateKeyHolder(privateKeyHolder)
			.withCertificateStore(certificateStore)
			.build0();
	}
	
	public void receiveFile(InputStream inputStream, OutputStream outputStream){
		try {
			SignEncryptUtils.decryptVerify(privateKeyHolder, nameX500, 
					certificateStore, inputStream, outputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public void sendFile(List<X500Name> reciepientNamesX500, InputStream inputStream, OutputStream outputStream){
		try {
			SignEncryptUtils.encrypt(certificateStore, reciepientNamesX500, inputStream, outputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

}
