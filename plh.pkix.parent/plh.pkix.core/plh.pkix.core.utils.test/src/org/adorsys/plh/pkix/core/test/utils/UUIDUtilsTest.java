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
	
	@SuppressWarnings("unused")
	@Test
	public void testBigIntegerUUID(){
		BigInteger bigInteger = UUIDUtils.toBigInteger(UUID.randomUUID());
		String string = bigInteger.toString(16).toUpperCase();
	}

}
