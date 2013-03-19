package org.adorsys.plh.pkix.core.test.utils;

import java.math.BigInteger;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.junit.Assert;
import org.junit.Test;

public class UUIDUtilsTest {

	@Test
	public void test() {
		byte[] uuidToBytes = UUIDUtils.newUUIDAsBytes();
		BigInteger bigInteger = new BigInteger(uuidToBytes);
		byte[] byteArray = bigInteger.toByteArray();
		Assert.assertArrayEquals(uuidToBytes, byteArray);
	}
	
	@Test
	public void testBigIntegerUUID(){
		UUID randomUUID = UUID.randomUUID();
//		BigInteger bigInteger = UUIDUtils.toBigInteger(randomUUID);
		byte[] uuidToBytes = UUIDUtils.uuidToBytes(randomUUID);
		BigInteger bigInteger = new BigInteger(uuidToBytes);
		byte[] byteArray = bigInteger.toByteArray();
		Assert.assertArrayEquals(uuidToBytes, byteArray);
		
		BigInteger bigInteger2 = new BigInteger(uuidToBytes);
		
		Assert.assertEquals(bigInteger, bigInteger2);
		String string1 = bigInteger.toString(16).toUpperCase();
		String string2 = bigInteger2.toString(16).toUpperCase();
		Assert.assertEquals(string1, string2);
	}
}
