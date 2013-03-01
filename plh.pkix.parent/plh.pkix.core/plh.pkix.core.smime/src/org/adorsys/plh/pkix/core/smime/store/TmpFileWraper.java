package org.adorsys.plh.pkix.core.smime.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.engines.CMSPWDStreamDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSPWDStreamEncryptor;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class TmpFileWraper {

	private final File tmpFile;
	private final char[] password;
	public TmpFileWraper() {
		password = UUID.randomUUID().toString().toCharArray();
		try {
			tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public long getSize() {
		return FileUtils.sizeOf(tmpFile);
	}

	public InputStream newInputStream() {
		try {
			for (OutputStream outputStream : outputStreams) {
				IOUtils.closeQuietly(outputStream);
			}
			outputStreams.clear();
			FileInputStream encryptedFileInputStream = new FileInputStream(tmpFile);
			InputStream decryptingInputStream = new CMSPWDStreamDecryptor()
				.withInputStream(encryptedFileInputStream)
				.toDecryptingInputStream(password);
			inputStreams.add(decryptingInputStream);
			inputStreams.add(encryptedFileInputStream);
			return decryptingInputStream;
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	public OutputStream newOutputStream() {
		try {
			for (InputStream inputStream : inputStreams) {
				IOUtils.closeQuietly(inputStream);
			}
			inputStreams.clear();
			FileOutputStream encryptedFileOutputStream = new FileOutputStream(tmpFile);
			OutputStream encryptingOutputStream = new CMSPWDStreamEncryptor()
				.withOutputStream(encryptedFileOutputStream)
				.toEncryptingOutputStream(password);
			outputStreams.add(encryptingOutputStream);
			outputStreams.add(encryptedFileOutputStream);
			return encryptingOutputStream;
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	private List<InputStream> inputStreams = new ArrayList<InputStream>();
	private List<OutputStream> outputStreams = new ArrayList<OutputStream>();
	public void dispose() {
		for (InputStream inputStream : inputStreams) {
			IOUtils.closeQuietly(inputStream);
		}
		inputStreams.clear();
		for (OutputStream outputStream : outputStreams) {
			IOUtils.closeQuietly(outputStream);
		}
		outputStreams.clear();
		FileUtils.deleteQuietly(tmpFile);
		
	}

	public byte[] toByteArray() {
		try {
			return FileUtils.readFileToByteArray(tmpFile);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}
