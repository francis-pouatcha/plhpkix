package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.util.Date;
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

public class PendingRequestFileNameHelperTest {

	@Test
	public void test() {
		Random random = new Random();
		BigInteger certReqId = new BigInteger(10, random);
		Date nextPoll = new Date();
		Date disposed = null;
		String fileName = PendingRequestFileNameHelper.makeFileName(certReqId, nextPoll, disposed);
		BigInteger certReqId2 = PendingRequestFileNameHelper.getCertReqId(fileName);
		Assert.assertEquals(certReqId, certReqId2);
		Date nextPoll2 = PendingRequestFileNameHelper.getNextPoll(fileName);
		Assert.assertEquals(nextPoll, nextPoll2);
		Date disposed2 = PendingRequestFileNameHelper.getDisposed(fileName);
		Assert.assertEquals(disposed, disposed2);
		
		disposed = new Date();
		fileName = PendingRequestFileNameHelper.makeFileName(certReqId, nextPoll, disposed);
		BigInteger certReqId3 = PendingRequestFileNameHelper.getCertReqId(fileName);
		Assert.assertEquals(certReqId, certReqId3);
		Date nextPoll3 = PendingRequestFileNameHelper.getNextPoll(fileName);
		Assert.assertEquals(nextPoll, nextPoll3);
		Date disposed3 = PendingRequestFileNameHelper.getDisposed(fileName);
		Assert.assertEquals(disposed, disposed3);
		
	}

}
