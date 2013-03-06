package org.adorsys.plh.pkix.core.utils.action;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Hold information needed by a workflow instance. Can persist persistable
 * information. Transient information must be restored as needed when the 
 * context is reactivated.
 * 
 * @author francis
 *
 */
public class ActionContext {

	private ActionContext parent;
	
	private Map<Class<?>,  Map<String, Object>> objectMap = new HashMap<Class<?>, Map<String, Object>>();
	
	public ActionContext(ActionContext parent) {
		this.parent = parent;
	}

	public ActionContext() {
	}

	@SuppressWarnings("unchecked")
	private <T> Map<String, T> getMap(Class<T> klass, boolean create){
		Map<String, Object> map = objectMap.get(klass);
		if(map==null && create){
			map = new HashMap<String, Object>();
			objectMap.put(klass, map);
		}
		return (Map<String, T>) map;
	}

	public <T> void put(Class<T> klass, String name, T object){
		Map<String, T> map = getMap(klass, true);
		if(name==null) name = klass.getName();
		map.put(name, object);
	}

	public <T> void put(Class<T> klass, T object){
		put(klass, klass.getName(), object);
	}
	
	public <T> boolean contains(Class<T> klass, String name){
		if(name==null) name=klass.getName();
		boolean result = false;
		Map<String, T> map = getMap(klass, false);
		if(map!=null){
			result = map.containsKey(name);
		}
		if(!result && parent!=null){
			result = parent.contains(klass, name);
		}
		return result;
	}
	
	/**
	 * Does not forward request to parent.
	 * @param klass
	 * @param name
	 * @return
	 */
	public <T> boolean remove(Class<T> klass, String name){
		Map<String, T> map = getMap(klass, false);
		if(map==null) return false;
		if(name==null) name=klass.getName();
		if(map.containsKey(name)){
			map.remove(name);
			if(map.isEmpty())objectMap.remove(klass);
			return true;
		}
		return false;
	}
	public <T> T get(Class<T> klass){
		return get(klass, klass.getName());
	}	
	public <T> T get(Class<T> klass, String name){
		if(name==null) name=klass.getName();
		T result = null;
		Map<String, T> map = getMap(klass, false);
		if(map!=null) {
			result = (T) map.get(name);
		}
		if(result==null && parent!=null) result = parent.get(klass, name);
		
		return result;
	}
	
	public void store(OutputStream outputStream){
		try {
			ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream);
			Set<Entry<Class<?>,Map<String,Object>>> byKlass = objectMap.entrySet();
			for (Entry<Class<?>, Map<String, Object>> mapEntries : byKlass) {
				Class<?> key = mapEntries.getKey();
				if(!ActionData.class.isAssignableFrom(key)) continue;
				Map<String, Object> map = mapEntries.getValue();
				Set<Entry<String,Object>> byName = map.entrySet();
				ByteArrayOutputStream subZipOutputStream = new ByteArrayOutputStream();
				ZipOutputStream subZipStream = new ZipOutputStream(subZipOutputStream);
				for (Entry<String, Object> objectEntry : byName) {
					ZipEntry subZipEntry = new ZipEntry(objectEntry.getKey());
					subZipStream.putNextEntry(subZipEntry);
					Object value = objectEntry.getValue();
					byte[] encoded;
					if(value!=null){
						ActionData obj = (ActionData) value;
						ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
						obj.writeTo(byteArrayOutputStream);
						encoded = byteArrayOutputStream.toByteArray();
					} else {
						encoded = new byte[0];
					}
					subZipStream.write(encoded);
					subZipStream.closeEntry();
				}
				byte[] byteArray = subZipOutputStream.toByteArray();
				ZipEntry subZipEntry = new ZipEntry(mapEntries.getKey().getName());
				zipOutputStream.putNextEntry(subZipEntry);
				zipOutputStream.write(byteArray);
				zipOutputStream.closeEntry();
			}
			zipOutputStream.close();
		} catch(Exception e){
			throw new IllegalStateException(e);
		}
	}
	
	public void load(InputStream  inputStream){
		try {
			ZipInputStream zipInputStream = new ZipInputStream(inputStream);
			ZipEntry zipEntry = zipInputStream.getNextEntry();
			while(zipEntry!=null){
				int size = (int) zipEntry.getSize();
				byte[] byteArray = new byte[size];
				zipInputStream.read(byteArray);
				zipInputStream.closeEntry();
				ZipInputStream subStream = new ZipInputStream(new ByteArrayInputStream(byteArray));
				HashMap<String,Object> map = new HashMap<String, Object>();
				@SuppressWarnings("unchecked")
				Class<? extends ActionData> klass = (Class<? extends ActionData>) Class.forName(zipEntry.getName());
				objectMap.put(klass, map);
				ZipEntry subEntry = subStream.getNextEntry();
				while(subEntry!=null){
					int size2 = (int) subEntry.getSize();
					ActionData actionData = null;
					if(size2>0){
						byte[] actionDatabytes = new byte[size2];
						subStream.read(actionDatabytes);
						actionData = klass.newInstance();
						actionData.readFrom(new ByteArrayInputStream(actionDatabytes));						
					}
					map.put(subEntry.getName(), actionData);
					subEntry = subStream.getNextEntry();
				}
				subStream.close();
				zipEntry = zipInputStream.getNextEntry();
			}
			zipInputStream.close();
		} catch(IOException e){
			throw new IllegalStateException(e);
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		} catch (InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		}
	}
}
