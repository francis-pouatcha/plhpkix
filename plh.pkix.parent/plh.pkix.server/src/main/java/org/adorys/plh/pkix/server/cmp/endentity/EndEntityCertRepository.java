package org.adorys.plh.pkix.server.cmp.endentity;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

@Stateless
public class EndEntityCertRepository {

	@PersistenceContext
	private EntityManager entityManager;

	public List<EndEntityCert> findEndEntityCertBySubjectAndIssuerName(X500Name subjectName, X500Name issuerName){
		TypedQuery<EndEntityCert> query = entityManager.createNamedQuery(EndEntityCert.BY_SUBJECT_ISSUER_NAME, EndEntityCert.class);
		query.setParameter("subjectName", subjectName.toString());
		query.setParameter("issuerName", issuerName.toString());
		return query.getResultList();
	}

	public List<EndEntityCert> findEndEntityCertBySubjectName(X500Name subjectName){
		TypedQuery<EndEntityCert> query = entityManager.createNamedQuery(EndEntityCert.BY_SUBJECT_NAME, EndEntityCert.class);
		query.setParameter("subjectName", subjectName.toString());
		return query.getResultList();
	}

	public EndEntityCert storeEndEntityCert(X509CertificateHolder certificate) {
        EndEntityCert endEntityCert = null;
		List<EndEntityCert> certs = findEndEntityCertBySubjectAndIssuerName(
				certificate.getSubject(), certificate.getIssuer());
		if(!certs.isEmpty()){
			endEntityCert = certs.iterator().next();
	        try {
				endEntityCert.setCertificate(certificate.getEncoded());
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
	        endEntityCert = entityManager.merge(endEntityCert);
		} else {
	        endEntityCert = new EndEntityCert();
	        endEntityCert.setSubjectName(certificate.getSubject().toString());
	        endEntityCert.setIssuerName(certificate.getIssuer().toString());
			endEntityCert.setId(UUID.randomUUID().toString());
	        try {
				endEntityCert.setCertificate(certificate.getEncoded());
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			entityManager.persist(endEntityCert);
		}
		return endEntityCert;
	}
	
	
}
