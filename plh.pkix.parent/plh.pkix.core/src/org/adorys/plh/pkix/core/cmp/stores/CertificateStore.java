package org.adorys.plh.pkix.core.cmp.stores;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificateStore {

	private Map<X500Name, List<X509CertificateHolder>> certificateHolderBySubject = new HashMap<X500Name, List<X509CertificateHolder>>();

	public boolean isEmpty(){
		return certificateHolderBySubject.isEmpty();
	}

	public void addCertificate(X509CertificateHolder certificate){
		X500Name subject = certificate.getSubject();
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subject);
		if(list==null){
			list = new ArrayList<X509CertificateHolder>();
			certificateHolderBySubject.put(subject, list);
		}
		list.add(certificate);
	}
	
	public X509CertificateHolder getCertificate(X500Name subject){
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subject);
		if(list==null || list.isEmpty()) return null;
		return list.get(0);
	}
	
	public X509CertificateHolder getCertificate(X500Name subject, X500Name issuer){
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subject);
		if(list==null || list.isEmpty()) return null;
		for (X509CertificateHolder x509CertificateHolder : list) {
			if(issuer.equals(x509CertificateHolder.getIssuer()))
				return x509CertificateHolder;
		}
		return null;
	}
}
