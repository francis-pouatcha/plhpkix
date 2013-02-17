package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;

import org.adorsys.plh.pkix.core.utils.Md5Utils;
import org.adorsys.plh.pkix.core.utils.PrivateKeyUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.PlhFileExtensions;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Stores certificates on a file.
 * 
 * For each subject the md5Hex sum of the distinguished name of the subjects is 
 * first used as file name to create the key store as a directory.
 * 
 * Inside the key store, the md5Hex sum of the distinguished name of the issuer is
 * used as the name of the certificate file.
 * 
 * @author francis
 *
 */
public class FileBasedKeyStore implements CertificateStore, PrivateKeyHolder {

	/**
	 * The directory in which these certificates are stored
	 */
	private final File directoryBase;	
	
	private final DeviceAccount deviceAccount;
	
	public FileBasedKeyStore(File directoryBase, DeviceAccount deviceAccount) {
		this.directoryBase = directoryBase;
		this.deviceAccount = deviceAccount;
		if(!directoryBase.exists()) directoryBase.mkdirs();
	}

	@Override
	public boolean isEmpty() {
		return directoryBase.list().length<=0;
	}

	@Override
	public void addCertificate(X509CertificateHolder certificate) {

		KeystoreDirDescriptor keystoreDirDescriptor = processKeyStoreFile(certificate);
		File keystoreDir = keystoreDirDescriptor.getKeystoreDir();
		if(!keystoreDir.exists()) keystoreDir.mkdirs();
		
		File certificateFile = keystoreDirDescriptor.getCertificateFile();
		try {
			FileUtils.writeByteArrayToFile(certificateFile, certificate.getEncoded());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public X509CertificateHolder getCertificate(X500Name subject) {
		return getCertificate(X500NameHelper.getCN(subject));
	}

	@Override
	public X509CertificateHolder getCertificate(String subjectCommonName) {
		KeystoreDirDescriptor keystoreDirDescriptor = processKeyStoreFile(subjectCommonName, subjectCommonName);
		File keystoreDir = keystoreDirDescriptor.getKeystoreDir();
		if(!keystoreDir.exists()) return null;
		File[] certFiles = keystoreDir.listFiles();
		for (File certFile : certFiles) {
			byte[] certFileByteArray;
			try {
				certFileByteArray = FileUtils.readFileToByteArray(certFile);
				return new X509CertificateHolder(certFileByteArray);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}
		return null;
	}

	@Override
	public X509CertificateHolder getCertificate(X500Name subject,
			X500Name issuer) {
		return getCertificate(X500NameHelper.getCN(subject), 
				X500NameHelper.getCN(issuer));
	}

	@Override
	public X509CertificateHolder getCertificate(String subjectCommonName,
			String issuerCommonName) {
		KeystoreDirDescriptor keystoreDirDescriptor = processKeyStoreFile(subjectCommonName, issuerCommonName);
		File certificateFile = keystoreDirDescriptor.getCertificateFile();
		if(!certificateFile.exists()) return null;
		byte[] certFileByteArray;
		try {
			certFileByteArray = FileUtils.readFileToByteArray(certificateFile);
			return new X509CertificateHolder(certFileByteArray);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	private KeystoreDirDescriptor processKeyStoreFile(X509CertificateHolder certificate){
		return processKeyStoreFile(certificate.getSubject(), certificate.getIssuer());
	}

	private KeystoreDirDescriptor processKeyStoreFile(X500Name subject, X500Name issuer){
		return processKeyStoreFile(X500NameHelper.getCN(subject), X500NameHelper.getCN(issuer));
	}
	
	private KeystoreDirDescriptor processKeyStoreFile(String subjectCN,String issuerCN){
		String subjectFilePrefix = Md5Utils.toMd5StringHex(subjectCN);
		File keystoreDir = new File(directoryBase, subjectFilePrefix+ PlhFileExtensions.KEY_STORE_DIR_EXT);
		String issuerFilePrefix = Md5Utils.toMd5StringHex(issuerCN);
		File certificateFile = new File(keystoreDir, issuerFilePrefix+PlhFileExtensions.CERTIFICATE_EXT);
		return new KeystoreDirDescriptor(keystoreDir, certificateFile);
	}
	
	static class KeystoreDirDescriptor{
		private final File keystoreDir;
		private final File certificateFile;
		public KeystoreDirDescriptor(File keystoreDir, File certificateFile) {
			this.keystoreDir = keystoreDir;
			this.certificateFile = certificateFile;
		}
		public File getKeystoreDir() {
			return keystoreDir;
		}
		public File getCertificateFile() {
			return certificateFile;
		}
	}

	@Override
	public void addKeyPair(PrivateKey privateKey, X509CertificateHolder certificate) 
	{
		File subjectPrivateKeyFile = getPrivateKeyFile(certificate);
		FileOutputStream subjectPrivateKeyFileOutputStream = null;
		try {
			subjectPrivateKeyFile.getParentFile().mkdirs();
			subjectPrivateKeyFileOutputStream = new FileOutputStream(subjectPrivateKeyFile);
			ByteArrayInputStream subjectPrivateKeyFileInputStream = new ByteArrayInputStream(
					PrivateKeyUtils.privateKeyToBytes(privateKey, ProviderUtils.bcProvider));
			deviceAccount.signEncrypt(subjectPrivateKeyFileInputStream, subjectPrivateKeyFileOutputStream);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		} finally {
			if(subjectPrivateKeyFileOutputStream!=null)
				IOUtils.closeQuietly(subjectPrivateKeyFileOutputStream);
		}
	}

	@Override
	public PrivateKey getPrivateKey(X509CertificateHolder certificate) {
		File subjectPrivateKeyFile = getPrivateKeyFile(certificate);
		if(!subjectPrivateKeyFile.exists()) return null;
		FileInputStream subjectPrivateKeyFileInputStream=null;
		try {
			subjectPrivateKeyFileInputStream = new FileInputStream(subjectPrivateKeyFile);
			ByteArrayOutputStream subjectPrivateKeyFileOutputStream = new ByteArrayOutputStream();
			deviceAccount.decrypVerify(subjectPrivateKeyFileInputStream, subjectPrivateKeyFileOutputStream);
			return PrivateKeyUtils.privateKeyFromBytes(subjectPrivateKeyFileOutputStream.toByteArray(), ProviderUtils.bcProvider);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		} finally {
			if(subjectPrivateKeyFileInputStream!=null)
				IOUtils.closeQuietly(subjectPrivateKeyFileInputStream);
		}
	}
	
	private File getPrivateKeyFile(X509CertificateHolder certificate){
		X500Name subject = certificate.getSubject();
		String subjectCN = X500NameHelper.getCN(subject);
		String subjectFilePrefix = Md5Utils.toMd5StringHex(subjectCN);
		return new File(directoryBase, subjectFilePrefix+PlhFileExtensions.PRIVATE_KEY_SIGNED_ENCRYPTED_EXT);
	}
}
