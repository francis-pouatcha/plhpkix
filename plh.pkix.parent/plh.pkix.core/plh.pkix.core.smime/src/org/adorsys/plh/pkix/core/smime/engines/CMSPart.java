package org.adorsys.plh.pkix.core.smime.engines;

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

import org.adorsys.plh.pkix.core.smime.store.TmpFileWraper;
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
    private TmpFileWraper tmpFileWraper;
    private byte[] content;

    
    BuilderChecker checker = new BuilderChecker(CMSPart.class);
	private CMSPart(TmpFileWraper tmpFileWraper) {
		checker.checkNull(tmpFileWraper);
		this.tmpFileWraper = tmpFileWraper;
		this.size = tmpFileWraper.getSize();
	}
	private CMSPart(byte[] content) {
		checker.checkNull(content);
		this.content = content;
		this.size = content.length;
	}
	private CMSPart() {
		this.tmpFileWraper = new TmpFileWraper();
	}

	public long getSize(){
    	return size;
    }
	
	private List<InputStream> openedInputStreams = new ArrayList<InputStream>();
	public InputStream newInputStream() throws FileNotFoundException{
		if(content!=null) return new ByteArrayInputStream(content);
		if(tmpFileWraper!=null) {
			InputStream fileInputStream = tmpFileWraper.newInputStream();
			openedInputStreams.add(fileInputStream);
			return new BufferedInputStream(fileInputStream);
		}
		return null;
	}
	
	private OutputStream outputStream;
	public OutputStream openStream() {
		if(tmpFileWraper==null || size!=INIT_SIZE) throw new IllegalStateException("Not a writable part");
		return outputStream = tmpFileWraper.newOutputStream();
	}

	public void writeTo(File dest) {
		try {
			OutputStream outputStream = new FileOutputStream(dest);
			writeTo(outputStream);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
	public void writeTo(OutputStream outputStream) {
		if(tmpFileWraper!=null) {
			InputStream fileInputStream;
			try {
				fileInputStream = tmpFileWraper.newInputStream();
				IOUtils.copy(fileInputStream, outputStream);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			IOUtils.closeQuietly(outputStream);
			IOUtils.closeQuietly(fileInputStream);
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
		if(tmpFileWraper!=null)
			tmpFileWraper.dispose();
		
		if(outputStream!=null)
			IOUtils.closeQuietly(outputStream);
	}
	
	public static CMSPart instanceFrom(InputStream inputStream) {
		try {
			TmpFileWraper createTempFile = new TmpFileWraper();
			
			OutputStream fileOutputStream = createTempFile.newOutputStream();
			try {
				IOUtils.copy(inputStream, fileOutputStream);
			} finally {
				IOUtils.closeQuietly(fileOutputStream);
			}
			long sizeOf = createTempFile.getSize();
			if(sizeOf<TRESHOLD){
				CMSPart cmsPart = new CMSPart(createTempFile.toByteArray());
				createTempFile.dispose();
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
				TmpFileWraper createTempFile = new TmpFileWraper();
				FileInputStream fileInputStream = new FileInputStream(srcFile);
				OutputStream newFileOutputStream = createTempFile.newOutputStream();
				IOUtils.copy(fileInputStream, newFileOutputStream);
				IOUtils.closeQuietly(fileInputStream);
				IOUtils.closeQuietly(newFileOutputStream);
				return new CMSPart(createTempFile);
			}
		} catch(IOException e){
			throw new IllegalStateException(e);
		}
	}
	
	public static CMSPart instanceEmpty(){
		return new CMSPart();
	}

}
