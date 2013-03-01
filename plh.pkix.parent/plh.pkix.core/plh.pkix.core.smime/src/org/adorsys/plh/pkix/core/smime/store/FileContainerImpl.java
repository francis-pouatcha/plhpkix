package org.adorsys.plh.pkix.core.smime.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedDecryptorVerifier;
import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedSignerEncryptor;
import org.adorsys.plh.pkix.core.smime.utils.CloseSubstreamsOutputStream;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;

public class FileContainerImpl implements FilesContainer {

	
	private PrivateKeyEntry containerPrivateKeyEntry;
	private File rootDirectory;

	@Override
	public FileWrapper newFile(String fileRelativePath) {
		return new FileWraperImpl(fileRelativePath, rootDirectory, this);
	}

	@Override
	public FileWrapper newFile(String dirRelativePath, String fileName) {		
		return new FileWraperImpl(dirRelativePath+File.separator+fileName, rootDirectory, this);
	}

	public CMSStreamedDecryptorVerifier newDecryptor(File file) {
		InputStream signedEncryptedInputStream;
		try {
			signedEncryptedInputStream = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
		return new CMSStreamedDecryptorVerifier()
			.withPrivateKeyEntry(containerPrivateKeyEntry)
			.withInputStream(signedEncryptedInputStream);
	}

	public OutputStream newOutputStream(File file) {
		if(!file.exists()) file.getParentFile().mkdirs();
		X509Certificate certificate = (X509Certificate) containerPrivateKeyEntry.getCertificate();
		FileOutputStream signedEncryptedOutputStream;
		try {
			signedEncryptedOutputStream = new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
		OutputStream signingEncryptingOutputStream = new CMSStreamedSignerEncryptor()
		.withRecipientCertificates(Arrays.asList(certificate))
		.withSignerCertificateChain(containerPrivateKeyEntry.getCertificateChain())
		.withOutputStream(signedEncryptedOutputStream)
		.signingEncryptingOutputStream(containerPrivateKeyEntry.getPrivateKey());
		CloseSubstreamsOutputStream closeSubstreamsOutputStream = new CloseSubstreamsOutputStream(signingEncryptingOutputStream);
		closeSubstreamsOutputStream.addSubStream(signedEncryptedOutputStream);
		return closeSubstreamsOutputStream;
	}
}
