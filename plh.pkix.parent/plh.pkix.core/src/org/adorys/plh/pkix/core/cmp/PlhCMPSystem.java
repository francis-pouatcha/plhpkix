package org.adorys.plh.pkix.core.cmp;

import java.security.Provider;
import java.security.Security;

import javax.crypto.NoSuchPaddingException;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class PlhCMPSystem {

	private static final String SYS_PROP_SERVER_NAME="org.adorys.plh.pkix.server.cmp.server_name";
	private static final String SYS_PROP_SERVER_EMAIL="org.adorys.plh.pkix.server.cmp.server_email";
	private static final String SYS_PROP_SERVER_PASSWORD="org.adorys.plh.pkix.server.cmp.server_password";
	private static final String SYS_PROP_KEYPAIR_ALGO="org.adorys.plh.pkix.server.cmp.keypair_algo";
	private static final String SYS_PROP_KEYPAIR_KEYSIZE="org.adorys.plh.pkix.server.cmp.keypair_keysize";

	public static final String PKIX_CMP_STRING = "application/pkixcmp";
	
	private static Provider provider = null;

	static {
		Security.addProvider(new BouncyCastleProvider());	
		provider = Security.getProvider("BC");
		if(provider==null) throw new IllegalStateException( new NoSuchPaddingException("BC"));
	}
	
	public static char[] getServerPassword(){
		return System.getProperty(SYS_PROP_SERVER_PASSWORD, "server_password").toCharArray();
	}
	
	public static String getKeyPairAlgorithm(){
		return System.getProperty(SYS_PROP_KEYPAIR_ALGO, "RSA");
	}
	
	public static int getKeySizeForKeyPair(){
		String ks = System.getProperty(SYS_PROP_KEYPAIR_KEYSIZE, "512");
		return Integer.parseInt(ks);
	}
	
	public static X500Name getServerName(){
		String serverName = System.getProperty(SYS_PROP_SERVER_NAME, "server");
		String serverEmail = System.getProperty(SYS_PROP_SERVER_EMAIL, "server@plhpkix.com");
		return X500NameHelper.makeX500Name(serverName, serverEmail);
	}

	public static Provider getProvider(){
		return provider;
	}
	
}
