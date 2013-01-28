package org.adorsys.plh.pkix.core.test.cms.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

public class SingEncryptScenarioTests {

	static Provider provider = PlhCMPSystem.getProvider();
	static char[] password = PlhCMPSystem.getServerPassword();
	
	static final String srcFile1 = "test/resources/rfc4210.pdf";
	static final String srcFile2 = "test/resources/rfc5652CMS.pdf";
	
	@Test
	public void testTimAndAlex() throws IOException {
		ClientMap clients = new ClientMap();

		String caCN="certAuth@plpkixhtest.biz";
		MockCMPandCMSClient caClient = new MockCMPandCMSClient(clients);
		caClient.register("certAuth", caCN);

		String timCN = "tim@plpkixhtest.biz";
		MockCMPandCMSClient timClient = new MockCMPandCMSClient(clients);
		timClient.register("tim", timCN);
		timClient.requestCertification(caCN);

		String alexCN = "alex@plpkixhtest.biz";
		MockCMPandCMSClient alexClient = new MockCMPandCMSClient(clients);
		alexClient.register("alex", alexCN);
		alexClient.requestCertification(caCN);
		
		// certificate exchange
		alexClient.fetchCertificate(timCN, caCN);
		timClient.fetchCertificate(alexCN, caCN);
		
		
		File fileSentByTim = new File(srcFile1);
		InputStream sentInputStream = new FileInputStream(srcFile1);
		String fileSentByTimToAlexName = "target/"+fileSentByTim.getName()+".sentByTimToAlex.signed.encrypted";
		File fileSentByTimToAlex = new File(fileSentByTimToAlexName);
		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToAlex );
		timClient.sendFile(caCN,sentInputStream, sentOutputStream, alexCN);
		IOUtils.closeQuietly(sentInputStream);
		IOUtils.closeQuietly(sentOutputStream);
		
		InputStream recievedInputStream = new FileInputStream(fileSentByTimToAlexName);
		File fileRecievedByAlexFromTim = new File("target/"+fileSentByTim.getName()+".recievedByAlexFromTim.decrypted.verified");
		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByAlexFromTim);
		alexClient.receiveFile(recievedInputStream, recivedOutputStream);
		IOUtils.closeQuietly(recievedInputStream);
		IOUtils.closeQuietly(recivedOutputStream);
	
		boolean contentEquals = FileUtils.contentEquals(
				new File(srcFile1), 
				new File(fileRecievedByAlexFromTim.getAbsolutePath()));
		Assert.assertTrue(contentEquals);
	}


	@Test
	public void testTimAndTim() throws IOException {
		ClientMap clients = new ClientMap();
		String caCN="certAuth@plpkixhtest.biz";
		MockCMPandCMSClient caClient = new MockCMPandCMSClient(clients);
		caClient.register("certAuth", caCN);

		String timCN = "tim@plpkixhtest.biz";
		MockCMPandCMSClient timClient = new MockCMPandCMSClient(clients);
		timClient.register("tim", timCN);
		timClient.requestCertification(caCN);
		
		File fileSentByTim = new File(srcFile1);
		InputStream sentInputStream = new FileInputStream(srcFile1);
		String fileSentByTimToTimName = "target/"+fileSentByTim.getName()+".sentByTimToTim.signed.encrypted";
		File fileSentByTimToTim = new File(fileSentByTimToTimName);
		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToTim );
		timClient.sendFile(caCN,sentInputStream, sentOutputStream, timCN);
		IOUtils.closeQuietly(sentInputStream);
		IOUtils.closeQuietly(sentOutputStream);
		
		InputStream recievedInputStream = new FileInputStream(fileSentByTimToTimName);
		String fileRecievedByTimFromTimName = "target/"+fileSentByTim.getName()+".recievedByTimFromTim.decrypted.verified";
		File  fileRecievedByTimFromTim = new File(fileRecievedByTimFromTimName);
		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByTimFromTim);
		timClient.receiveFile(recievedInputStream, recivedOutputStream);
		IOUtils.closeQuietly(recievedInputStream);
		IOUtils.closeQuietly(recivedOutputStream);
	
		boolean contentEquals = FileUtils.contentEquals(
				new File(srcFile1), 
				new File(fileRecievedByTimFromTim.getAbsolutePath()));
		Assert.assertTrue(contentEquals);
	}
}
