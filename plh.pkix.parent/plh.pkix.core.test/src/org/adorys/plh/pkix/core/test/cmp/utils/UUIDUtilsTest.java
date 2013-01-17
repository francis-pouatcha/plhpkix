package org.adorys.plh.pkix.core.test.cmp.utils;

import java.math.BigInteger;

import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
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

}
