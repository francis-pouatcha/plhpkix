package plh.pkix.client.messaging.mail.reciever;

import javax.mail.Store;

public class StoreHolder {

	public StoreHolder(String email, Store store) {
		super();
		this.email = email;
		this.store = store;
	}

	private final String email;
	
	private Store store;

	public Store getStore() {
		return store;
	}

	public void setStore(Store store) {
		this.store = store;
	}

	public String getEmail() {
		return email;
	}
}
