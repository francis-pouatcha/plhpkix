package org.adorsys.plh.pkix.server.cmp.endentity;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Version;
import javax.validation.constraints.NotNull;

@Entity
@NamedQueries({
	@NamedQuery(name=EndEntityKey.BY_SUBJECT_NAME, 
			query="SELECT e FROM EndEntityKey e WHERE e.subjectName=:subjectName")
})
public class EndEntityKey {
	public static final String BY_SUBJECT_NAME="ENDENTITYKEY_BY_SUBJECT_NAME";

    @Id
	private String id;
    
    @Version
    private Integer version;

	@NotNull
	private String subjectName;

	/**
	 * Certificate issued by the server.
	 */
	@Lob
	@NotNull
	private byte[] encryptedKeyData;

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

	public String getSubjectName() {
		return subjectName;
	}

	public void setSubjectName(String subjectName) {
		this.subjectName = subjectName;
	}

	public byte[] getEncryptedKeyData() {
		return encryptedKeyData;
	}

	public void setEncryptedKeyData(byte[] encryptedKeyData) {
		this.encryptedKeyData = encryptedKeyData;
	}
}
