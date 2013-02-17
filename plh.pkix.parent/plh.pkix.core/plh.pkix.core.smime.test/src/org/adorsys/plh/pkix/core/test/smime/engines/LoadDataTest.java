package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;

public class LoadDataTest {

	@Test
	public void test() throws FileNotFoundException {
		InputStream inputStream = new FileInputStream(
				"test/resources/rfc4210.pdf");
		Assert.assertNotNull(inputStream);
	}

}
