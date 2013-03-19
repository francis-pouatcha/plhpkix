package org.adorsys.plh.pkix.core.utils.contact;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

public interface ContactManager {

	public abstract void addCertEntry(X509CertificateHolder certHolder)
			throws PlhCheckedException;

	public abstract void addPrivateKeyEntry(Key key, Certificate[] chain)
			throws PlhCheckedException;

	public abstract void importIssuedCertificate(
			org.bouncycastle.asn1.x509.Certificate[] certArray)
			throws PlhCheckedException;

	public abstract <T extends Entry> T findEntryBySerialNumber(Class<T> klass,
			BigInteger serialNumber);

	public abstract <T extends Entry> T findEntryByPublicKeyInfo(
			Class<T> klass, SubjectPublicKeyInfo subjectPublicKeyInfo);

	public abstract <T extends Entry> List<T> findEntriesByPublicKeyInfo(
			Class<T> klass, SubjectPublicKeyInfo subjectPublicKeyInfo);

	public abstract <T extends Entry> T findEntryByPublicKeyIdentifier(
			Class<T> klass, byte[] publicKeyIdentifier);

	public abstract <T extends Entry> List<T> findEntriesByPublicKeyIdentifier(
			Class<T> klass, byte[] publicKeyIdentifier);

	public abstract <T extends Entry> T findEntryBySubjectKeyIdentifier(
			Class<T> klass, byte[] subjectKeyIdentifierBytes);

	public abstract <T extends Entry> List<T> findEntriesBySubjectKeyIdentifier(
			Class<T> klass, byte[] subjectKeyIdentifierBytes);

	public abstract <T extends Entry> T findMessageEntryByIssuerCertificate(
			Class<T> klass, X509CertificateHolder... issuerCertificates);

	public abstract <T extends Entry> List<T> findMessageEntriesByIssuerCertificate(
			Class<T> klass, X509CertificateHolder... issuerCertificates);

	public abstract <T extends Entry> T findMessageEntryByEmail(Class<T> klass,
			String... emails);

	public abstract <T extends Entry> List<T> findMessageEntriesByEmail(
			Class<T> klass, String... emails);

	public abstract <T extends Entry> T findCaEntryBySubject(Class<T> klass,
			X500Name... subjects);

	public abstract <T extends Entry> List<T> findCaEntriesBySubject(
			Class<T> klass, X500Name... subjects);

	public abstract <T extends Entry> T findEntryByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases);

	public abstract <T extends Entry> T findEntryByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases);

	public abstract <T extends Entry> List<T> findEntriesByAlias(
			Class<T> klass, List<KeyStoreAlias> keyStoreAliases);

	public abstract <T extends Entry> List<T> findEntriesByAlias(
			Class<T> klass, KeyStoreAlias... keyStoreAliases);

	public abstract List<KeyStoreAlias> keyStoreAliases();

	public abstract Set<TrustAnchor> getTrustAnchors();

	public abstract Set<CertStore> findCertStores(
			X509CertificateHolder... certificates);

	public abstract Set<CertStore> findCertStores(
			List<X509CertificateHolder> certificates);

	public abstract boolean isAuthenticated();

	public abstract X509CRL getCrl();
	
	public abstract PrivateKeyEntry getMainMessagePrivateKeyEntry();

	public abstract PrivateKeyEntry getMainCaPrivateKeyEntry();

	public abstract Set<String> listContacts();

}