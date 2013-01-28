package org.adorys.plh.pkix.core.cmp.stores;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Hold a list of certificate for a client. 
 * 
 * The certificate store is case insensitive.
 * 
 * @author francis
 *
 */
public class CertificateStore {

	private Map<String, List<X509CertificateHolder>> certificateHolderBySubject = new HashMap<String, List<X509CertificateHolder>>();

	public boolean isEmpty(){
		return certificateHolderBySubject.isEmpty();
	}

	public void addCertificate(X509CertificateHolder certificate){
		X500Name subject = certificate.getSubject();
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subject);
		if(list==null){
			list = new ArrayList<X509CertificateHolder>();
			certificateHolderBySubject.put(X500NameHelper.getCN(subject), list);
		}
		list.add(certificate);
	}
	
	public X509CertificateHolder getCertificate(X500Name subject){
		String subjectCN = X500NameHelper.getCN(subject);
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subjectCN);
		if(list==null || list.isEmpty()) return null;
		return list.get(0);
	}

	public X509CertificateHolder getCertificate(String subjectCommonName){
		String subjectCN = subjectCommonName.toLowerCase();
		List<X509CertificateHolder> list = certificateHolderBySubject.get(subjectCN);
		if(list==null || list.isEmpty()) return null;
		return list.get(0);
	}
	
	public X509CertificateHolder getCertificate(X500Name subject, X500Name issuer){
		String subjectCN = X500NameHelper.getCN(subject);
		String issuerCN = X500NameHelper.getCN(issuer);

		List<X509CertificateHolder> list = certificateHolderBySubject.get(subjectCN);
		if(list==null || list.isEmpty()) return null;
		for (X509CertificateHolder x509CertificateHolder : list) {
			if(issuerCN.equals(X500NameHelper.getCN(x509CertificateHolder.getIssuer())))
				return x509CertificateHolder;
		}
		return null;
	}

	public X509CertificateHolder getCertificate(String subjectCommonName, String issuerCommonName){
		String subjectCN = subjectCommonName.toLowerCase();
		String issuerCN = issuerCommonName.toLowerCase();

		List<X509CertificateHolder> list = certificateHolderBySubject.get(subjectCN);
		if(list==null || list.isEmpty()) return null;
		for (X509CertificateHolder x509CertificateHolder : list) {
			if(issuerCN.equals(X500NameHelper.getCN(x509CertificateHolder.getIssuer())))
				return x509CertificateHolder;
		}
		return null;
	}
}
