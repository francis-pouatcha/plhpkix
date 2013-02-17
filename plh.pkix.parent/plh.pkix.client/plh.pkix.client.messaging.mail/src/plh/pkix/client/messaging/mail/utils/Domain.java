package plh.pkix.client.messaging.mail.utils;

public class Domain {

	/**
	 * your-domain.
	 */
	private String domainName;

	/**
	 * The server host of the domain.
	 */
	private String serverHost;
	
	private String port;
	
	private String domainURL;

	/**
	 * Username configuration.
	 */
	private static UsernameConfiguration usernameConfiguration =
		new UsernameConfiguration();

	public String getDomainName() {
		return domainName;
	}

	public void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	public String getServerHost() {
		return serverHost;
	}

	public void setServerHost(String serverHost) {
		this.serverHost = serverHost;
	}

	public String getPort() {
		return port;
	}

	public void setPort(String port) {
		this.port = port;
	}

	public String getDomainURL() {
		return domainURL;
	}

	public void setDomainURL(String domainURL) {
		this.domainURL = domainURL;
	}

	public static UsernameConfiguration getUsernameConfiguration() {
		return usernameConfiguration;
	}

	public static void setUsernameConfiguration(
			UsernameConfiguration usernameConfiguration) {
		Domain.usernameConfiguration = usernameConfiguration;
	}

}
