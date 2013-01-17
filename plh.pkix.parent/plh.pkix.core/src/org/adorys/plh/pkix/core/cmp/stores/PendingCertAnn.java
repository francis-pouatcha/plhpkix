package org.adorys.plh.pkix.core.cmp.stores;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class PendingCertAnn {

	private static final Map<X500Name, PendingCertAnn> instances = new HashMap<X500Name, PendingCertAnn>();

	public static PendingCertAnn getInstance(X500Name role){
		PendingCertAnn pendingCertAnns = instances.get(role);
		if(pendingCertAnns==null){
			pendingCertAnns = new PendingCertAnn();
			instances.put(role, pendingCertAnns);
		}
		return pendingCertAnns;
	}
	
	private LinkedList<X509CertificateHolder> x509CertificateHolders = new LinkedList<X509CertificateHolder>();
	
	public X509CertificateHolder getNext(){
		return x509CertificateHolders.poll();
	}
	
	public void add(X509CertificateHolder certificateHolder){
		x509CertificateHolders.add(certificateHolder);
	}
}
