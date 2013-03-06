package org.adorsys.plh.pkix.core.cmp;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * The end entity is the holder of and id that is associated with all certificates 
 * generated by the same person. The information is stored into the distinguished 
 * name of the certificate under the RDN: {@link BCStyle#UNIQUE_IDENTIFIER}. It
 * doesn't matter whether the DN is extracted from the subject field of from the first directoryName
 * out of subjectAltName extension of the certificate. It is advisable to use the 
 * {@link X500NameHelper#readSubjectDN(org.bouncycastle.cert.X509CertificateHolder)} method
 * to read the distinguished name associated with a certificate since it implements
 * DN details as describes in RFC5280#4.1.2.6.
 * 
 * 
 * @author francis
 *
 */
public interface CMPEndEntity {
	
	public String getEntityIdentifier();

}
