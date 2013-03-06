package org.adorsys.plh.pkix.core.smime.store;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedDecryptorVerifier;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * @author francis
 *
 */
public class FileWraperImpl implements FileWrapper{

	private static final String KEYSTORE_FILE_NAME="keystore";
	
	private String path;
	private File file;
	private File rootFile;
	
	private FileContainerImpl container;
	
	private CMSStreamedDecryptorVerifier decryptorVerifier;
	public FileWraperImpl(String path, File rootFile, FileContainerImpl container) {
		super();
		this.path = path;
		this.rootFile = rootFile;
		this.file = new File(rootFile, path);
		this.container = container;
	}

	@Override
	public InputStream newInputStream() {
		if(file.isDirectory()) throw new IllegalArgumentException("FIle is a directory");
		decryptorVerifier = container.newDecryptor(file);
		InputStream decryptingInputStream =  decryptorVerifier.decryptingInputStream();
		return decryptingInputStream;
	}

	@Override
	public OutputStream newOutputStream() {
		if(file.isDirectory()) throw new IllegalArgumentException("FIle is a directory");
		file.getParentFile().mkdirs();
		return container.newOutputStream(file);
	}

	@Override
	public String getFileRelativePath() {
		return path;
	}

	@Override
	public boolean delete() {
		return file.delete();
	}

	@Override
	public boolean exists() {
		return file.exists();
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public String getParent() {
		File parentFile = file.getParentFile();
		if(parentFile.equals(rootFile)) return "/";
		
		return path.substring(0,path.lastIndexOf(file.getName()));
	}

	@Override
	public void integrityCheck() {
		if(decryptorVerifier==null) return;
		decryptorVerifier.verify();
	}

	@Override
	public String[] list() {
		return file.list();
	}

	@Override
	public FileWrapper newChild(String name) {
		return new FileWraperImpl(name, file, container);
	}

	private KeyStoreWraper keyStoreWraper;
	@Override
	public X509CertificateHolder loadKeyCertificate(String publicKeyIdentifier) {
		return getKeyStoreWraper().findKeyCertificate(publicKeyIdentifier);
	}
	@Override
	public KeyStoreWraper getKeyStoreWraper() {
		if(keyStoreWraper==null){
			FileWrapper keyStoreFile = newChild(KEYSTORE_FILE_NAME);
			keyStoreWraper = new KeyStoreWraper(keyStoreFile, null, container.getPublicKeyIdentifier().toCharArray());
		}
		return keyStoreWraper;
	}
}
