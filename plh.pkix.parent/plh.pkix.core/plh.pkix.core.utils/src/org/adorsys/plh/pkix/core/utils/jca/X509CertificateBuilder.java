package org.adorsys.plh.pkix.core.utils.jca;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Build a certificate based on information passed to this object.
 * 
 * The subjectSampleCertificate can be used as a model. The ca can create some of the fields manually so
 * so modifying suggestions provided by the sample certificate.
 * 
 * The object shall not be reused. After the build method is called, this object is not reusable.
 * 
 * 
 * @author francis
 *
 */
public class X509CertificateBuilder {

	private static Provider provider = ProviderUtils.bcProvider;

	private boolean ca;

	private X500Name subjectDN;

	private PublicKey subjectPublicKey;

	private Date notBefore;

	private Date notAfter;

	private X509CertificateHolder subjectSampleCertificate;

	private X509CertificateHolder issuerCertificate;

	private int keyUsage=-1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltNames;

	private AuthorityInformationAccess authorityInformationAccess;

	private final BuilderChecker checker = new BuilderChecker(X509CertificateBuilder.class);
	public X509CertificateHolder build(PrivateKey issuerPrivatekey) {
		checker.checkDirty();
		
		if(subjectSampleCertificate!=null){
			if(subjectPublicKey==null) subjectPublicKey=V3CertificateUtils.extractPublicKey(subjectSampleCertificate);
			if(subjectDN==null) subjectDN=subjectSampleCertificate.getSubject();
			if(notBefore==null) notBefore=subjectSampleCertificate.getNotBefore();
			if(notAfter==null) notAfter=subjectSampleCertificate.getNotAfter();
			
			if(!keyUsageSet)copyKeyUsage(subjectSampleCertificate);
			
			if(subjectAltNames==null){
				Extension extension = subjectSampleCertificate.getExtension(X509Extension.subjectAlternativeName);
				if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
			}
			
			if(authorityInformationAccess==null){
				Extension extension = subjectSampleCertificate.getExtension(X509Extension.authorityInfoAccess);
				if(extension!=null) authorityInformationAccess = AuthorityInformationAccess.getInstance(extension.getParsedValue());
			}
		}
		
		if(subjectPublicKey==null)throw new IllegalArgumentException("Missing subject public key");
		if(subjectDN==null) throw new IllegalArgumentException("Missing subject distinguished name");
		if(notBefore==null) throw new IllegalArgumentException("Missing validity date notBefore");
		if(notAfter==null) throw new IllegalArgumentException("Missing validity date not after");

		X500Name issuerDN = null;
		BasicConstraints basicConstraints = null;
		if(issuerCertificate==null){// self signed certificate
			issuerDN = subjectDN;
			if(ca){
				// self signed ca certificate
				basicConstraints = new BasicConstraints(true);
			} else {
				basicConstraints = new BasicConstraints(false);
			}
		} else {			
			// check is issuerCertificate is ca certificate
			Extension basicConstraintsExtension = issuerCertificate.getExtension(X509Extension.basicConstraints);
			BasicConstraints issuerBasicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
			if(!issuerBasicConstraints.isCA()) throw new IllegalArgumentException("Issuer certificate is not for ca");
			
			if(!KeyUsageUtils.hasAllKeyUsage(issuerCertificate, KeyUsage.keyCertSign))
				throw new IllegalArgumentException("Issuer certificate is not for key signature");	

			// prepare inputs
			issuerDN = issuerCertificate.getSubject();

			if(ca){// ca signing another ca certificate
				BigInteger pathLenConstraint = issuerBasicConstraints.getPathLenConstraint();
				if(pathLenConstraint==null){
					pathLenConstraint = BigInteger.ONE;
				} else {
					pathLenConstraint = pathLenConstraint.add(BigInteger.ONE);
				}
				basicConstraints = new BasicConstraints(pathLenConstraint.intValue());
				withKeyUsage(KeyUsage.keyCertSign);
			} else {// ca issuing a simple certificate
				basicConstraints = new BasicConstraints(false);
			}
		}

		BigInteger serial = UUIDUtils.toBigInteger(UUID.randomUUID());

		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subjectDN,subjectPublicKey);

		JcaX509ExtensionUtils extUtils;
		try {
			extUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}

		try {
			v3CertGen.addExtension(X509Extension.basicConstraints,true, basicConstraints);

			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier,false, 
					extUtils.createSubjectKeyIdentifier(subjectPublicKey));
			
			if(issuerCertificate==null){
				v3CertGen.addExtension(X509Extension.authorityKeyIdentifier,false,
						extUtils.createAuthorityKeyIdentifier(subjectPublicKey));
			} else {
				v3CertGen.addExtension(X509Extension.authorityKeyIdentifier,false,
						extUtils.createAuthorityKeyIdentifier(issuerCertificate));
			}
			
			if(keyUsageSet){
				v3CertGen.addExtension(X509Extension.keyUsage,
						true, new KeyUsage(this.keyUsage));
			}

			if(subjectAltNames!=null)
				v3CertGen.addExtension(X509Extension.subjectAlternativeName, false, subjectAltNames);
			
			if(authorityInformationAccess!=null)
				v3CertGen.addExtension(X509Extension.authorityInfoAccess, false, authorityInformationAccess);
				
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		}

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1WithRSA")
					.setProvider(provider).build(issuerPrivatekey);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		return v3CertGen.build(signer);

	}
	
	private void copyKeyUsage(X509CertificateHolder issuerCertificate) {
		int ku = KeyUsageUtils.getKeyUsage(issuerCertificate);
		if(ku!=-1)withKeyUsage(ku);
	}

	public X509CertificateBuilder withCa(boolean ca) {
		this.ca = ca;
		return this;
	}

	public X509CertificateBuilder withSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}

	public X509CertificateBuilder withSubjectPublicKey(PublicKey subjectPublicKey) {
		this.subjectPublicKey = subjectPublicKey;
		return this;
	}

	public X509CertificateBuilder withNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public X509CertificateBuilder withNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public X509CertificateBuilder withSubjectSampleCertificate(
			X509CertificateHolder subjectSampleCertificate) {
		this.subjectSampleCertificate = subjectSampleCertificate;
		return this;
	}

	public X509CertificateBuilder withIssuerCertificate(
			X509CertificateHolder issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
		return this;
	}

	public X509CertificateBuilder withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public X509CertificateBuilder withSubjectAltNames(GeneralNames subjectAltNames) {
		if(this.subjectAltNames==null){
			this.subjectAltNames = new GeneralNames(subjectAltNames.getNames());
		} else {
			ArrayList<GeneralName> nameList = new ArrayList<GeneralName>();
			GeneralName[] names1 = this.subjectAltNames.getNames();
			for (GeneralName generalName : names1) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			GeneralName[] names2 = subjectAltNames.getNames();
			for (GeneralName generalName : names2) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			GeneralName[] names = nameList.toArray(new GeneralName[nameList.size()]);
			this.subjectAltNames = new GeneralNames(names);
		}
		return this;
	}

	public X509CertificateBuilder withSubjectAltName(GeneralName subjectAltName) {
		if(this.subjectAltNames==null){
			this.subjectAltNames = new GeneralNames(subjectAltName);
		} else {
			ArrayList<GeneralName> nameList = new ArrayList<GeneralName>();
			GeneralName[] names1 = this.subjectAltNames.getNames();
			for (GeneralName generalName : names1) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			nameList.add(subjectAltName);
			GeneralName[] names = nameList.toArray(new GeneralName[nameList.size()]);
			this.subjectAltNames = new GeneralNames(names);
		}
		return this;
	}
	
	public X509CertificateBuilder withAuthorityInformationAccess(
			AuthorityInformationAccess authorityInformationAccess) {
		this.authorityInformationAccess = authorityInformationAccess;
		return this;
	}
}
