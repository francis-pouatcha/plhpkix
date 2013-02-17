package org.adorsys.plh.pkix.messaging.server;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Version;
import javax.validation.constraints.NotNull;

@Entity
@NamedQueries({
	@NamedQuery(name=MessagingAccount.BY_EMAIL, 
			query="SELECT m FROM MessagingAccount m WHERE m.email=:email")
})
public class MessagingAccount {

	public static final String BY_EMAIL="MESSAGINGACCOUNT_BY_EMAIL";
	
	@Id
	private String id;
    
    @Version
    private Integer version;

	@NotNull
	private String email;
	
	private String passwdHash;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public Integer getVersion() {
		return version;
	}

	public void setVersion(Integer version) {
		this.version = version;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPasswdHash() {
		return passwdHash;
	}

	public void setPasswdHash(String passwdHash) {
		this.passwdHash = passwdHash;
	}
}
