package org.adorsys.plh.pkix.server.cmp.endentity;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Runtime representation of an end entity.
 * 
 * @author francis
 *
 */
public class EndEntityHolder {

	private final Map<String, X509CertificateHolder> certificateMap = new HashMap<String, X509CertificateHolder>();

	private String subjectName;

	EndEntityHolder(String subjectName,
			X509CertificateHolder... serverCertificateHolder) 
	{
		this.subjectName = subjectName;
		for (X509CertificateHolder certificateHolder : serverCertificateHolder) {
			certificateMap.put(certificateHolder.getIssuer().toString(), certificateHolder);
		}
	}

	EndEntityHolder(String subjectName,
			Collection<X509CertificateHolder> serverCertificateHolders) 
	{
		this.subjectName = subjectName;
		for (X509CertificateHolder certificateHolder : serverCertificateHolders) {
			certificateMap.put(certificateHolder.getIssuer().toString(), certificateHolder);
		}
	}
	
	public X509CertificateHolder getCertificate(String issuerName) {
		return certificateMap.get(issuerName);
	}
	public Collection<X509CertificateHolder> getCertificates() {
		return Collections.unmodifiableCollection(certificateMap.values());
	}

	public String getSubjectName() {
		return subjectName;
	}
}
