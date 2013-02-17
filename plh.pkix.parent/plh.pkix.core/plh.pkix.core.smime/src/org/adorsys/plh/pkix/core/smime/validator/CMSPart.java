package org.adorsys.plh.pkix.core.smime.validator;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
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

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

/**
 * Holds byte used handle by the CMS signers and verifiers.
 * 
 * @author francis
 *
 */
public class CMSPart {

	private static final long INIT_SIZE = -1l;
	private static final long TRESHOLD=1024l;
    private long size=INIT_SIZE;
    private File temFile;
    private byte[] content;

    
    BuilderChecker checker = new BuilderChecker(CMSPart.class);
	private CMSPart(File temFile) {
		checker.checkNull(temFile);
		this.temFile = temFile;
		this.size = FileUtils.sizeOf(temFile);
	}
	private CMSPart(byte[] content) {
		checker.checkNull(content);
		this.content = content;
		this.size = content.length;
	}
	private CMSPart() {
		try {
			this.temFile = File.createTempFile(UUID.randomUUID().toString(), null);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public long getSize(){
    	return size;
    }
	
	private List<InputStream> openedInputStreams = new ArrayList<InputStream>();
	public InputStream newInputStream() throws FileNotFoundException{
		if(content!=null) return new ByteArrayInputStream(content);
		if(temFile!=null) {
			FileInputStream fileInputStream = new FileInputStream(temFile);
			openedInputStreams.add(fileInputStream);
			return new BufferedInputStream(fileInputStream);
		}
		return null;
	}
	
	private OutputStream outputStream;
	public OutputStream openStream() {
		if(temFile==null || size!=INIT_SIZE) throw new IllegalStateException("Not a writable part");
		try {
			return outputStream = new FileOutputStream(temFile);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	public void writeTo(File dest) {
		if(temFile!=null)
			try {
				FileUtils.copyFile(temFile, dest);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		if(content!=null)
			try {
				FileUtils.writeByteArrayToFile(dest,content);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
	}
	public void writeTo(OutputStream outputStream) {
		if(temFile!=null) {
			FileInputStream fileInputStream;
			try {
				fileInputStream = new FileInputStream(temFile);
				IOUtils.copy(fileInputStream, outputStream);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			IOUtils.closeQuietly(outputStream);
		} else if(content!=null){
			try {
				IOUtils.copy(new ByteArrayInputStream(content), outputStream);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}
	}
	
	public void dispose(){
		for (InputStream inputStream : openedInputStreams) {
			IOUtils.closeQuietly(inputStream);
		}
		if(temFile!=null)
			FileUtils.deleteQuietly(temFile);
		
		if(outputStream!=null)
			IOUtils.closeQuietly(outputStream);
	}
	
	public static CMSPart instanceFrom(InputStream inputStream) {
		try {
			File createTempFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
			FileOutputStream fileOutputStream = new FileOutputStream(createTempFile);
			try {
				IOUtils.copy(inputStream, fileOutputStream);
			} finally {
				IOUtils.closeQuietly(fileOutputStream);
			}
			long sizeOf = FileUtils.sizeOf(createTempFile);
			if(sizeOf<TRESHOLD){
				CMSPart cmsPart = new CMSPart(FileUtils.readFileToByteArray(createTempFile));
				FileUtils.deleteQuietly(createTempFile);
				return cmsPart;
			} else {
				return new CMSPart(createTempFile);
			}
		} catch(IOException e){
			throw new IllegalStateException(e);
		}
	}

	public static CMSPart instanceFrom(File srcFile) {
		try {
			long sizeOf = FileUtils.sizeOf(srcFile);
			if(sizeOf<TRESHOLD){
				return new CMSPart(FileUtils.readFileToByteArray(srcFile));
			} else {
				File destFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
				FileUtils.copyFile(srcFile, destFile);
				return new CMSPart(destFile);
			}
		} catch(IOException e){
			throw new IllegalStateException(e);
		}
	}
	
	public static CMSPart instanceEmpty(){
		return new CMSPart();
	}
}
