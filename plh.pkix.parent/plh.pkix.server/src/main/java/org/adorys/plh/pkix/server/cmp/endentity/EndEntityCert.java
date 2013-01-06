package org.adorys.plh.pkix.server.cmp.endentity;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Version;
import javax.validation.constraints.NotNull;

@Entity
@NamedQueries({
	@NamedQuery(name=EndEntityCert.BY_SUBJECT_NAME, 
			query="SELECT e FROM EndEntityCert e WHERE e.subjectName=:subjectName"),
	@NamedQuery(name=EndEntityCert.BY_SUBJECT_ISSUER_NAME, 
			query="SELECT e FROM EndEntityCert e WHERE e.subjectName=:subjectName AND e.issuerName=:issuerName")
})
public class EndEntityCert {
	public static final String BY_SUBJECT_NAME="ENDENTITYCERT_BY_SUBJECT_NAME";
	public static final String BY_SUBJECT_ISSUER_NAME="ENDENTITYCERT_BY_SUBJECT_ISSUER_NAME";

    @Id
	private String id;
    
    @Version
    private Integer version;

	@NotNull
	private String subjectName;

	@NotNull
	private String issuerName;

	/**
	 * Certificate issued by the server.
	 */
	@Lob
	@NotNull
	private byte[] certificate;

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

	public String getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}

	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}
}
