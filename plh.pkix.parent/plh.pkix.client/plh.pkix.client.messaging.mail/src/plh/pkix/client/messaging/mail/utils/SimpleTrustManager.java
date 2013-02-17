package plh.pkix.client.messaging.mail.utils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.net.ssl.X509TrustManager;
public class SimpleTrustManager implements X509TrustManager{

	public static final ThreadLocal<Map<String, Object>> TRUST = new ThreadLocal<Map<String, Object>>();
	public static final String CERTIFCATES_KEY = "CERTIFICATES";
	public static final String AUTH_TYPE_KEY = "AUTH_TYPE";
	
	public void checkClientTrusted(X509Certificate[] ax509certificate, String s)
			throws CertificateException {
		// get certificate from holder, and check
		Map<String, Object> map = TRUST.get();
		if(map!=null){
			map.put(CERTIFCATES_KEY, ax509certificate);
			map.put(AUTH_TYPE_KEY, s);
		}
	}

	public void checkServerTrusted(X509Certificate[] ax509certificate, String s)
			throws CertificateException {
		// get certificate from holder, and check
		Map<String, Object> map = TRUST.get();
		if(map!=null){
			map.put(CERTIFCATES_KEY, ax509certificate);
			map.put(AUTH_TYPE_KEY, s);
		}
	}

	public X509Certificate[] getAcceptedIssuers() {
	    return new X509Certificate[ 0];
	}
}
