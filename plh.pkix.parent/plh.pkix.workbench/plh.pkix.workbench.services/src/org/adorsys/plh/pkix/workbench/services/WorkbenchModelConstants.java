package org.adorsys.plh.pkix.workbench.services;

/**
 * Maintains common names for model elements. Used to reference those 
 * model elements in contributing modules.
 * 
 * @author francis
 *
 */
public interface WorkbenchModelConstants {

	/**
	 * Main application window. Embed following here.
	 * - Account registration window: generally displayed if no account is active
	 * 		or if the user decides to register a new account.
	 * - Account selection window: generally displayed if the are active account
	 * 		register with this device and none of them is selected yet. 
	 * - Navigator and editor workbench: generally active when a account is selected.
	 */
	public static final String defaultPartSashContainer = "plh.pkix.workbench.desktop.defaultPartSashContainer";
	
	/**
	 * This is the window in which to store navigators(views). This Part will later be modified
	 * to have a select box where all views active in the part are displayed.
	 * 
	 * Sample views are:
	 *   - File browser: displays the account files. By just mapping the user's file system.
	 *   - Contact browser: displays all contacts of this account.
	 *   - Any application can add it's object browser to this view.
	 */
	public static final String primaryNavigationStack = "org.eclipse.e4.primaryNavigationStack";
	
	/**
	 * This is the core presentation view. If for example a contact object is selected in the 
	 * primaryNavigationStack, the contact editor view will be displayed on this window.
	 */
	public static final String primaryDataStack = "org.eclipse.e4.primaryDataStack";
	
	/**
	 * This view displays the structure of the object being edited in the primaryDAtaStack.
	 * It can be used either to navigate through large Structures or even to display a
	 * sub menu. If for example a contact is being displayed in the primaryDataStack,
	 * the structured field of that contact can be displayed there. So are the commands 
	 * associated with that contact.
	 */
	public static final String secondaryNavigationStack = "org.eclipse.e4.secondaryNavigationStack";
	
	/**
	 * This is the window at the bottom of the primary data window. Will be used to manage
	 * the secondary informations like errors, notifications, search results, etc...
	 */
	public static final String secondaryDataStack ="org.eclipse.e4.secondaryDataStack";
}
