package org.adorsys.plh.pkix.core.utils;

import java.security.Provider;
import java.security.Security;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProviderUtils {

	private static final String SYS_PROP_KEYPAIR_ALGO="org.adorys.plh.pkix.server.cmp.keypair_algo";
	private static final String SYS_PROP_KEYPAIR_KEYSIZE="org.adorys.plh.pkix.server.cmp.keypair_keysize";
	public static final Provider bcProvider;

	static {
		Security.addProvider(new BouncyCastleProvider());	
		bcProvider = Security.getProvider("BC");
		if(bcProvider==null) throw new IllegalStateException( new NoSuchPaddingException("BC"));
	}
	
	public static String getKeyPairAlgorithm(){
		return System.getProperty(SYS_PROP_KEYPAIR_ALGO, "RSA");
	}
	
	public static int getKeySizeForKeyPair(){
		String ks = System.getProperty(SYS_PROP_KEYPAIR_KEYSIZE, "512");
		return Integer.parseInt(ks);
	}
	
}
