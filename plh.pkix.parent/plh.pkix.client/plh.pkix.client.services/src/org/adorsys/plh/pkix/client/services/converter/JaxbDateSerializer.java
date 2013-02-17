package org.adorsys.plh.pkix.client.services.converter;

import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class JaxbDateSerializer extends XmlAdapter<String, Date> {

	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss:SSS Z");
	
	@Override
	public String marshal(Date date) throws Exception {
		return dateFormat.format(date);
	}

	@Override
	public Date unmarshal(String date) throws Exception {
		return dateFormat.parse(date);
	}
}
