package org.adorsys.plh.pkix.core.utils;

import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;

public class KeyEntryAndCertificate {

	private final PrivateKeyEntry privateKeyEntry;
	private final TrustedCertificateEntry trustedCertificateEntry;
	private final X509CertificateHolder certHolder;

	public KeyEntryAndCertificate(Entry entry) {
		if(entry instanceof PrivateKeyEntry){
			privateKeyEntry = (PrivateKeyEntry) entry;
			trustedCertificateEntry = null;
			certHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
			
		} else if (entry instanceof TrustedCertificateEntry){
			trustedCertificateEntry = (TrustedCertificateEntry) entry;
			privateKeyEntry=null;
			certHolder = V3CertificateUtils.getX509CertificateHolder(trustedCertificateEntry.getTrustedCertificate());
		}else {
			trustedCertificateEntry = null;
			privateKeyEntry=null;
			certHolder = null;
		}
	}

	public X509CertificateHolder getCertHolder() {
		return certHolder;
	}
	
	public List<X509CertificateHolder> getCertificateChain(){
		if(trustedCertificateEntry!=null)
			return Collections.singletonList(certHolder);
		
		if(privateKeyEntry!=null){
			List<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
			Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
			for (Certificate certificate : certificateChain) {
				result.add(V3CertificateUtils.getX509CertificateHolder(certificate));
			}
			return result;
		}
		
		return null;
	}
	
	public boolean hasCertificate(){
		return certHolder!=null;
	}
	
	public static List<KeyEntryAndCertificate> filterCertHolders(List<KeyStore.Entry> entrie){
		List<KeyEntryAndCertificate> result = new ArrayList<KeyEntryAndCertificate>();
		for (Entry entry : entrie) {
			KeyEntryAndCertificate keyEntryAndCertificate = new KeyEntryAndCertificate(entry);
			if(keyEntryAndCertificate.hasCertificate())
				result.add(keyEntryAndCertificate);
		}
		
		return result ;
	}
}
