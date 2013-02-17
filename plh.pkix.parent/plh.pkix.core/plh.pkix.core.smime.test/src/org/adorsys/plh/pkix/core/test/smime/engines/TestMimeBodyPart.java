package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class TestMimeBodyPart {
	
	@Test
	public void testMimeBodyPart() throws IOException, MessagingException{
        MimeBodyPart document = new MimeBodyPart();
        File rawFile = new File("test/resources/rfc4210.pdf");
        document.attachFile(rawFile);
        File targetFile = new File("target/rfc4210.pdf");
        document.saveFile(targetFile);
        File mimeEncoded = new File("target/rfc4210.pdf.mime");
        FileOutputStream fileOutputStream = new FileOutputStream(mimeEncoded);
        document.writeTo(fileOutputStream);
        IOUtils.closeQuietly(fileOutputStream);
        InputStream inputStream = document.getInputStream();
        File targetFile2 = new File("target/rfc4210_2.pdf");
        FileOutputStream fileOutputStream2 = new FileOutputStream(targetFile2);
        IOUtils.copy(inputStream, fileOutputStream2);
        IOUtils.closeQuietly(inputStream);
        IOUtils.closeQuietly(fileOutputStream2);
        Assert.assertTrue(FileUtils.contentEquals(rawFile, targetFile));
        Assert.assertFalse(FileUtils.contentEquals(rawFile, mimeEncoded));
        Assert.assertTrue(FileUtils.contentEquals(rawFile, targetFile2));
        FileUtils.deleteQuietly(targetFile);
        FileUtils.deleteQuietly(mimeEncoded);
        FileUtils.deleteQuietly(targetFile2);
	}

}
