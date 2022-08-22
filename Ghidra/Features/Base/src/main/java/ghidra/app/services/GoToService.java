/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.services;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/**
 * The GoToService provides a general service for plugins to generate GoTo
 * events.  The provider of this service will take care of interfacing with
 * any history service that may be available.
 * <p>
 * This class will execute all {@code goTo} calls on the Java Swing thread.   This will happen in
 * a blocking manner if the client calls from any other thread.  This has the potential to lead
 * to deadlocks if the client is using custom synchronization.  Care must be taken to not be
 * holding any lock that will cause the Swing thread to block when using this class from any other
 * thread.   To work around this issue, clients can always call this service from within a
 * {@link Swing#runLater(Runnable)} call, which will prevent any deadlock issues.
 */
@ServiceInfo(defaultProvider = GoToServicePlugin.class, description = "Navigate to a program location")
public interface GoToService {

	/**
	 * Characters that are allowed in words that the GoToService can use. These
	 * typically represent library name delimiters.
	 */
	public static final char[] VALID_GOTO_CHARS = new char[] { '.', ':', '*' };

	/**
	 * Generates a GoTo event and handles any history state that needs to be saved.  This method
	 * will attempt to find the program that contains the given ProgramLocation.
	 *
	 * @param loc location to go to
	 * @return true if the go to was successful
	 * @see #goTo(ProgramLocation, Program)
	 */
	public boolean goTo(ProgramLocation loc);

	/**
	 * Generates a GoTo event and handles any history state that needs to be saved.  This
	 * overloaded version of {@link #goTo(Address)} uses the given program as the program within
	 * which to perform the GoTo.  If the given program does not contain the given address, then
	 * the GoTo will not be performed and false will be returned.  Passing <code>null</code> as the
	 * <code>program</code> parameter will cause this method to attempt to find a program that
	 * contains the given ProgramLocation.
	 *
	 * @param loc location to go to
	 * @param program the program within which to perform the GoTo
	 * @return true if the go to was successful
	 * @see #goTo(ProgramLocation)
	 */
	public boolean goTo(ProgramLocation loc, Program program);

	/**
	 * Generates a GoTo event to the given location in the given program.
	 *
	 * @param navigatable the destination navigatable
	 * @param loc the location
	 * @param program program
	 * @return true if the go to was successful
	 */
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program);

	/**
	 * Generates a GoTo event to the given address.  The refAddress is used to determine if
	 * there is a specific symbol reference from that reference.
	 *
	 * @param navigatable the destination navigatable
	 * @param program program
	 * @param address the destination address
	 * @param refAddress the from reference address
	 * @return true if the go to was successful
	 */
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress);

	/**
	 * Generates a GoTo event to the given address.  The fromAddress is used to determine if
	 * there is a specific symbol reference from the current address.
	 *
	 * @param fromAddress the current address
	 * @param address the address to goto
	 * @return true if the go to was successful
	 */
	public boolean goTo(Address fromAddress, Address address);

	/**
	 * Generates a GoTo event to the given address for the specific navigatable.
	 *
	 * @param navigatable the destination navigatable
	 * @param goToAddress the address to goto
	 * @return true if the go to was successful
	 */
	public boolean goTo(Navigatable navigatable, Address goToAddress);

	/**
	 * Generates a GoTo event to the gotoAddress.
	 * @param goToAddress the address to goto
	 * @return true if the go to was successful
	 * @see #goTo(Address, Program)
	 */
	public boolean goTo(Address goToAddress);

	/**
	 * Generates a GoTo event to the gotoAddress.   This overloaded version of
	 * {@link #goTo(Address)} uses the given program as the program within which to perform the
	 * GoTo.  If the given program does not contain the given address, then the GoTo will not be
	 * performed and false will be returned.  Passing <code>null</code> as the <code>program</code>
	 * parameter will cause this method to attempt to find a program that contains the given
	 * ProgramLocation.
	 *
	 * @param goToAddress the address to goto
	 * @param program the program within which to perform the GoTo
	 * @return true if the go to was successful
	 * @see #goTo(Address)
	 */
	public boolean goTo(Address goToAddress, Program program);

	/**
	 * Navigate to either the external program location or address linkage location.  Specific
	 * behavior may vary based upon implementation.
	 *
	 * @param externalLoc external location
	 * @param checkNavigationOption if true the service navigation option will be used to determine
	 * 		if navigation to the external program will be attempted, or if navigation to the
	 * 		external linkage location within the current program will be attempted.  If false, the
	 * 		implementations default behavior will be performed.
	 * @return true if either navigation to the external program or to a linkage location was
	 * 		completed successfully.
	 */
	public boolean goToExternalLocation(ExternalLocation externalLoc,
			boolean checkNavigationOption);

	/**
	 * Navigate to either the external program location or address linkage location.  Specific
	 * behavior may vary based upon implementation.
	 *
	 * @param navigatable Navigatable
	 * @param externalLoc external location
	 * @param checkNavigationOption if true the service navigation option will be used to determine
	 * 		if navigation to the external program will be attempted, or if navigation to the
	 * 		external linkage location within the current program will be attempted.  If false, the
	 * 		implementations default behavior will be performed.
	 * @return true if either navigation to the external program or to a linkage location was
	 * 		completed successfully.
	 */
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation externalLoc,
			boolean checkNavigationOption);

	/**
	 * Generates a GoTo event for the given query.
	 * <p>
	 * If the query results in more than one location, a list of locations will be displayed.
	 * If the query results in only one location, then a goto event will be fired(except for a
	 * wildcard query in which case a list will still be displayed.
	 * <p>
	 * The listener will be notified after query and will indicate the query status.
	 *
	 * @param fromAddr The address used to determine the scope of the query
	 * @param queryData the query input data
	 * @param listener the listener that will be notified when the query completes
	 * @param monitor the task monitor
	 * @return true if the queryInput is found or appears to be a wildcard search
	 */
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor);

	/**
	 * Generates a GoTo event for the given query.
	 * <p>
	 * If the query results in more than one location, a list of locations will be displayed.
	 * If the query results in only one location, then a goto event will be fired(except for a
	 * wildcard query in which case a list will still be displayed.
	 * <p>
	 * The listener will be notified after query and will indicate the query status.
	 *
	 * @param navigatable the destination for the go to event
	 * @param fromAddr The address used to determine the scope of the query
	 * @param queryData the query input data
	 * @param listener the listener that will be notified when the query completes
	 * @param monitor the task monitor
	 * @return true if the queryInput is found or appears to be a wildcard search
	 */
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor);

	/**
	 * Returns the default navigatable that is the destination for GoTo events.
	 * @return the navigatable
	 */
	public Navigatable getDefaultNavigatable();

	@Deprecated(forRemoval = true, since = "10.2")
	public GoToOverrideService getOverrideService();

	@Deprecated(forRemoval = true, since = "10.2")
	public void setOverrideService(GoToOverrideService override);
}
