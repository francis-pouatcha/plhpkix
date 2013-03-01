package org.adorsys.plh.pkix.core.utils.action;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MapBasedProcessingResult<K,V extends ErrorsAndNotificationsHolder> extends SimpleENHolder {
	private final List<K> keyList = new ArrayList<K>();
	private final Map<K,V> valueMap = new HashMap<K, V>();

	public List<K> getKeys() {
		return Collections.unmodifiableList(keyList);
	}
	
	public V get(K key){
		return valueMap.get(key);
	}

	@Override
	public boolean hasError() {
		Collection<V> values = valueMap.values();
		for (V v : values) {
			if(v.hasError()) return true;
		}
		return super.hasError();
	}

	@Override
	public boolean hasNotification() {
		Collection<V> values = valueMap.values();
		for (V v : values) {
			if(v.hasNotification()) return true;
		}
		return super.hasNotification();
	}	
	
	public void addValue(K key, V value){
		if(!keyList.contains(key))
			keyList.add(key);
		valueMap.put(key, value);
	}
}

