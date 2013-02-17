package org.adorsys.plh.pkix.server.cmp.endentity;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

@Stateless
public class EndEntityCertRepository {

	@PersistenceContext
	private EntityManager entityManager;

	public List<EndEntityCert> findEndEntityCertBySubjectAndIssuerName(X500Name subjectName, X500Name issuerName){
		TypedQuery<EndEntityCert> query = entityManager.createNamedQuery(EndEntityCert.BY_SUBJECT_ISSUER_NAME, EndEntityCert.class);
		query.setParameter("subjectName", X500NameHelper.getCN(subjectName));
		query.setParameter("issuerName", X500NameHelper.getCN(issuerName));
		return query.getResultList();
	}

	public List<EndEntityCert> findEndEntityCertBySubjectName(X500Name subjectName){
		TypedQuery<EndEntityCert> query = entityManager.createNamedQuery(EndEntityCert.BY_SUBJECT_NAME, EndEntityCert.class);
		query.setParameter("subjectName", X500NameHelper.getCN(subjectName));
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
	        endEntityCert.setSubjectName(X500NameHelper.getCN(certificate.getSubject()));
	        endEntityCert.setIssuerName(X500NameHelper.getCN(certificate.getIssuer()));
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
