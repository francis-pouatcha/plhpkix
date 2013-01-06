package org.adorys.plh.pkix.server.test.cmp.core.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;

import org.adorys.plh.pkix.server.cmp.core.PlhCMPSystem;
import org.adorys.plh.pkix.server.cmp.core.utils.PrivateKeyUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class PrivateKeyUtilsTest {

	static PrivateKey privateKey;
	static Provider provider = PlhCMPSystem.getProvider();
	static  char[] password = PlhCMPSystem.getServerPassword();
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
        KeyPairGenerator kGen;
		try {
			kGen = KeyPairGenerator.getInstance(PlhCMPSystem.getKeyPairAlgorithm(), provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
        
		kGen.initialize(PlhCMPSystem.getKeySizeForKeyPair());
        KeyPair keyPair = kGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Test
	public void testEncryptPrivateKey() throws Exception {
		PrivateKeyUtils.encryptPrivateKey(privateKey, provider, password);
	}

	@Test
	public void testDecryptPrivateKey() throws Exception {
		byte[] encryptedPrivateKey = PrivateKeyUtils.encryptPrivateKey(privateKey, provider, password);
		PrivateKey decryptedPrivateKey = PrivateKeyUtils.decryptPrivateKey(encryptedPrivateKey, password, provider);
		Assert.assertEquals(privateKey, decryptedPrivateKey);
	}

	@Test
	public void testPrivateKeyFromBytes() throws Exception {
		byte[] privateKeyBytes = PrivateKeyUtils.privateKeyToBytes(privateKey, provider);
		PrivateKey privateKeyFromBytes = PrivateKeyUtils.privateKeyFromBytes(privateKeyBytes, provider);
		Assert.assertEquals(privateKey, privateKeyFromBytes);
	}

	@Test
	public void testPrivateKeyToBytes() throws Exception {
		PrivateKeyUtils.privateKeyToBytes(privateKey, provider);
	}

}
