package org.adorsys.plh.pkix.core.utils.jca;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.PublicKeyUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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

	private GeneralNames subjectAltName;

	private AuthorityInformationAccess authorityInformationAccess;

	private boolean dirty;
	public X509CertificateHolder build(PrivateKey issuerPrivatekey) {
		
		if(dirty) throw new IllegalStateException("Builder is dirty. Create and populate a new one.");
		dirty=true;// gone
		
		if(subjectSampleCertificate!=null){
			if(subjectPublicKey==null) subjectPublicKey=extractPublicKey(subjectSampleCertificate);
			if(subjectDN==null) subjectDN=subjectSampleCertificate.getSubject();
			if(notBefore==null) notBefore=subjectSampleCertificate.getNotBefore();
			if(notAfter==null) notAfter=subjectSampleCertificate.getNotAfter();
			
			if(!keyUsageSet)copyKeyUsage(issuerCertificate);
			
			if(subjectAltName==null){
				Extension extension = subjectSampleCertificate.getExtension(X509Extension.subjectAlternativeName);
				if(extension!=null) subjectAltName = GeneralNames.getInstance(extension.getParsedValue());
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
			
			if(validateKeyUsage(issuerCertificate, KeyUsage.keyCertSign))
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
				addKeyUsage(KeyUsage.keyCertSign);
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

			if(subjectAltName!=null)
				v3CertGen.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
			
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
	
	private void copyKeyUsage(X509CertificateHolder issuerCertificate2) {
		Extension keyUsageExtension = issuerCertificate.getExtension(X509Extension.keyUsage);
		if(keyUsageExtension!=null){
            DERBitString ku = KeyUsage.getInstance(keyUsageExtension.getParsedValue().toASN1Primitive());
            addKeyUsage(ku.getBytes()[0] & 0xff);
		}
	}

	private boolean validateKeyUsage(X509CertificateHolder holder, int keyUsageBits){
    	Extension extension = holder.getExtension(X509Extension.keyUsage);
        if (extension != null){
            DERBitString ku = KeyUsage.getInstance(extension);
            int bits = ku.getBytes()[0] & 0xff;
            return (bits & keyUsageBits) == keyUsageBits;
        }
        return false;
    }

	private final PublicKey extractPublicKey(
			X509CertificateHolder subjectCertificate) {
		try {
			return PublicKeyUtils.getPublicKey(subjectCertificate, provider);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public X509CertificateBuilder setCa(boolean ca) {
		this.ca = ca;
		return this;
	}

	public X509CertificateBuilder setSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}

	public X509CertificateBuilder setSubjectPublicKey(PublicKey subjectPublicKey) {
		this.subjectPublicKey = subjectPublicKey;
		return this;
	}

	public X509CertificateBuilder setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public X509CertificateBuilder setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public X509CertificateBuilder setSubjectSampleCertificate(
			X509CertificateHolder subjectSampleCertificate) {
		this.subjectSampleCertificate = subjectSampleCertificate;
		return this;
	}

	public X509CertificateBuilder setIssuerCertificate(
			X509CertificateHolder issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
		return this;
	}

	public X509CertificateBuilder addKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public X509CertificateBuilder setSubjectAltName(GeneralNames subjectAltName) {
		this.subjectAltName = subjectAltName;
		return this;
	}

	public X509CertificateBuilder setAuthorityInformationAccess(
			AuthorityInformationAccess authorityInformationAccess) {
		this.authorityInformationAccess = authorityInformationAccess;
		return this;
	}

}
