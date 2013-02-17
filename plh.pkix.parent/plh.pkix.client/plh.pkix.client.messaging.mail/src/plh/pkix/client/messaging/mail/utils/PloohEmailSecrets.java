package plh.pkix.client.messaging.mail.utils;

import java.util.Properties;


public class PloohEmailSecrets {
	
	private final Properties properties;
	
	public PloohEmailSecrets(Properties properties) {
		this.properties = properties;
	}
	
	public String get(String key){
		return properties.getProperty(key);
	}

	public String getSmtpsHost() {
		return get("mail.smtps.host");
	}

	public String getSmtpsPort() {
		return get("mail.smtps.port");
	}

	public String getSmtpsFrom() {
		return get("mail.smtps.from");
	}

	public String getSmtpsUserName() {
		return get("mail.smtps.username");
	}

	public String getSmtpsPassword() {
		return get("mail.smtps.password");
	}

	public String getSmtpsKeystore() {
		return get("mail.smime.pkcs12.keystore");
	}

	public String getSmtpsKeystorePass() {
		return get("mail.smime.pkcs12.keystorepass");
	}

	public String getSmtpsKeyAlias() {
		return get("mail.smime.pkcs12.alias");
	}
}
