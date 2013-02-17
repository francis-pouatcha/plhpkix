package org.adorsys.plh.pkix.client.services.datatypes;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.adorsys.plh.pkix.client.services.converter.JaxbDateSerializer;
import org.adorsys.plh.pkix.core.utils.Md5Utils;


@XmlRootElement(name="EmailAccount")
@XmlAccessorType(XmlAccessType.FIELD)
public class EmailAccount {

	private static final String STORAGE_PREFIX_STRING = "EmailAccount";

	private String email;

	private String username;

	private String password;

	private String host;

	private String port = "-1";

	private String protocol= "imaps";
	
	private String folder = "INBOX";

	private String smtpPort = "-1";

	private String smtpProtocol = "smtp";

	private String smtpHost;

	@XmlJavaTypeAdapter(JaxbDateSerializer.class)
	private Date lastImport;

	private String lastImportComment;

	/**
	 * Base 64 encoded server certificate
	 */
	private String serverCertificate;
	
	private boolean advanced;

	private final List<String> imapFolders = new ArrayList<String>();
	public static final int LASTINPORTEDPOSITION = 0;
	public static final int LASTCOUNTPOSITION = 1;

	private String lastProcessedMessageId;

	public EmailAccount() {
		imapFolders.add("0");// lastInportedPosition
		imapFolders.add("0");// lastCountPosition
	}

	public EmailAccount(String email, String password) {
		this();
		this.email = email;
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPort() {
		return port;
	}

	public void setPort(String port) {
		this.port = port;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getFolder() {
		return folder;
	}

	public void setFolder(String folder) {
		this.folder = folder;
	}

	public void setLastImport(Date lastImport) {
		this.lastImport = lastImport;
	}

	public String getLastImportComment() {
		return lastImportComment;
	}

	public void setLastImportComment(String lastImportComment) {
		this.lastImportComment = lastImportComment;
	}

	public String getSmtpPort() {
		return smtpPort;
	}

	public void setSmtpPort(String smtpPort) {
		this.smtpPort = smtpPort;
	}

	public String getSmtpProtocol() {
		return smtpProtocol;
	}

	public void setSmtpProtocol(String smtpProtocol) {
		this.smtpProtocol = smtpProtocol;
	}

	public String getSmtpHost() {
		return smtpHost;
	}

	public void setSmtpHost(String smtpHost) {
		this.smtpHost = smtpHost;
	}

	public String getServerCertificate() {
		return serverCertificate;
	}

	public void setServerCertificate(String serverCertificate) {
		this.serverCertificate = serverCertificate;
	}
	@Override
	public String toString() {
		if (email != null)
			return email;
		return super.toString();
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public Date getLastImport() {
		return lastImport;
	}

	public String getLastProcessedMessageId() {
		return lastProcessedMessageId;
	}

	public void setLastProcessedMessageId(String lastProcessedMessageId) {
		this.lastProcessedMessageId = lastProcessedMessageId;
	}

	public List<String> getImapFolders() {
		return imapFolders;
	}

	public int getLastInported(){
		String string = imapFolders.get(LASTINPORTEDPOSITION);
		return Integer.parseInt(string);
	}

	public int getLastCount(){
		String string = imapFolders.get(LASTCOUNTPOSITION);
		return Integer.parseInt(string);
	}
	
	public void setLastInported(int lastImported){
		imapFolders.set(LASTINPORTEDPOSITION, lastImported+"");
	}
	
	public void setLastCount(int lastCount){
		imapFolders.set(LASTCOUNTPOSITION,lastCount+"");
	}

	public boolean isAdvanced() {
		return advanced;
	}

	public void setAdvanced(boolean advanced) {
		this.advanced = advanced;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (advanced ? 1231 : 1237);
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		result = prime * result + ((folder == null) ? 0 : folder.hashCode());
		result = prime * result + ((host == null) ? 0 : host.hashCode());
		result = prime * result
				+ ((imapFolders == null) ? 0 : imapFolders.hashCode());
		result = prime * result
				+ ((lastImport == null) ? 0 : lastImport.hashCode());
		result = prime
				* result
				+ ((lastImportComment == null) ? 0 : lastImportComment
						.hashCode());
		result = prime
				* result
				+ ((lastProcessedMessageId == null) ? 0
						: lastProcessedMessageId.hashCode());
		result = prime * result
				+ ((password == null) ? 0 : password.hashCode());
		result = prime * result + ((port == null) ? 0 : port.hashCode());
		result = prime * result
				+ ((protocol == null) ? 0 : protocol.hashCode());
		result = prime
				* result
				+ ((serverCertificate == null) ? 0 : serverCertificate
						.hashCode());
		result = prime * result
				+ ((smtpHost == null) ? 0 : smtpHost.hashCode());
		result = prime * result
				+ ((smtpPort == null) ? 0 : smtpPort.hashCode());
		result = prime * result
				+ ((smtpProtocol == null) ? 0 : smtpProtocol.hashCode());
		result = prime * result
				+ ((username == null) ? 0 : username.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EmailAccount other = (EmailAccount) obj;
		if (advanced != other.advanced)
			return false;
		if (email == null) {
			if (other.email != null)
				return false;
		} else if (!email.equals(other.email))
			return false;
		if (folder == null) {
			if (other.folder != null)
				return false;
		} else if (!folder.equals(other.folder))
			return false;
		if (host == null) {
			if (other.host != null)
				return false;
		} else if (!host.equals(other.host))
			return false;
		if (imapFolders == null) {
			if (other.imapFolders != null)
				return false;
		} else if (!imapFolders.equals(other.imapFolders))
			return false;
		if (lastImport == null) {
			if (other.lastImport != null)
				return false;
		} else if (!lastImport.equals(other.lastImport))
			return false;
		if (lastImportComment == null) {
			if (other.lastImportComment != null)
				return false;
		} else if (!lastImportComment.equals(other.lastImportComment))
			return false;
		if (lastProcessedMessageId == null) {
			if (other.lastProcessedMessageId != null)
				return false;
		} else if (!lastProcessedMessageId.equals(other.lastProcessedMessageId))
			return false;
		if (password == null) {
			if (other.password != null)
				return false;
		} else if (!password.equals(other.password))
			return false;
		if (port == null) {
			if (other.port != null)
				return false;
		} else if (!port.equals(other.port))
			return false;
		if (protocol == null) {
			if (other.protocol != null)
				return false;
		} else if (!protocol.equals(other.protocol))
			return false;
		if (serverCertificate == null) {
			if (other.serverCertificate != null)
				return false;
		} else if (!serverCertificate.equals(other.serverCertificate))
			return false;
		if (smtpHost == null) {
			if (other.smtpHost != null)
				return false;
		} else if (!smtpHost.equals(other.smtpHost))
			return false;
		if (smtpPort == null) {
			if (other.smtpPort != null)
				return false;
		} else if (!smtpPort.equals(other.smtpPort))
			return false;
		if (smtpProtocol == null) {
			if (other.smtpProtocol != null)
				return false;
		} else if (!smtpProtocol.equals(other.smtpProtocol))
			return false;
		if (username == null) {
			if (other.username != null)
				return false;
		} else if (!username.equals(other.username))
			return false;
		return true;
	}
	
	public static final String makeEmailAccountRelFileName(String emailAccountStrict){
		return STORAGE_PREFIX_STRING + File.pathSeparator +Md5Utils.toMd5StringHex(emailAccountStrict);
	}
}
