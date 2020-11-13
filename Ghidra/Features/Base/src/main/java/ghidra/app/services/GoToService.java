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
import ghidra.util.task.TaskMonitor;

/**
 * The GoToService provides a general service for plugins to generate GoTo
 * events.  The provider of this service will take care of interfacing with
 * any history service that may be available.
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
	 * overloaded version of {@link #goTo(Address)} uses the given program as the program 
	 * within which to perform the GoTo.  If the given program does not contain the given 
	 * address, then the GoTo will not be performed and false will be returned.  Passing 
	 * <code>null</code> as the <code>program</code> parameter will cause this method to attempt to find
	 * a program that contains the given ProgramLocation.
	 * 
	 * @param loc location to go to
	 * @param program the program within which to perform the GoTo
	 * @return true if the go to was successful
	 * @see #goTo(ProgramLocation)
	 */
	public boolean goTo(ProgramLocation loc, Program program);

	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program);

	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress);

	/**
	 * Generates a GoTo event to the goToAddress or symbol.  The currentAddress is used to
	 * determine if there is a specific symbol reference from the current address.
	 * @param currentAddress the current address
	 * @param goToAddress the address to goto
	 * @return true if the go to was successful
	 */
	public boolean goTo(Address currentAddress, Address goToAddress);

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
	 * {@link #goTo(Address)} uses the given program as the program within which to
	 * perform the GoTo.  If the given program does not contain the given address, then the 
	 * GoTo will not be performed and false will be returned.  Passing <code>null</code> as the 
	 * <code>program</code> parameter will cause this method to attempt to find
	 * a program that contains the given ProgramLocation.
	 * 
	 * @param goToAddress the address to goto
	 * @param program the program within which to perform the GoTo
	 * @return true if the go to was successful
	 * @see #goTo(Address)
	 */
	public boolean goTo(Address goToAddress, Program program);

	/**
	 * Navigate to either the external program location or address linkage location.  
	 * Specific behavior may vary based upon implementation.
	
	 * @param externalLoc external location
	 * @param checkNavigationOption if true the service navigation 
	 * option will be used to determine if navigation to the external program will be 
	 * attempted, or if navigation to the external linkage location within the current
	 * program will be attempted.  If false, the implementations default behavior
	 * will be performed.
	 * @return true if either navigation to the external program or to a
	 * linkage location was completed successfully.
	 */
	public boolean goToExternalLocation(ExternalLocation externalLoc,
			boolean checkNavigationOption);

	/**
	 * Navigate to either the external program location or address linkage location.  
	 * Specific behavior may vary based upon implementation.
	 * 
	 * @param navigatable Navigatable
	 * @param externalLoc external location
	 * @param checkNavigationOption if true the service navigation 
	 * option will be used to determine if navigation to the external program will be 
	 * attempted, or if navigation to the external linkage location within the current
	 * program will be attempted.  If false, the implementations default behavior
	 * will be performed.
	 * @return true if either navigation to the external program or to a
	 * linkage location was completed successfully.
	 */
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation externalLoc,
			boolean checkNavigationOption);

	/**
	 * Parses the input string as either: 
	 * 	an address/symbol expression (0x1000+5,  or LAB1000+5)  
	 *  a symbol wildcard expression (LAB*,  LAB?100)
	 *  a symbol lookup
	 *  an address lookup
	 * 
	 * If the query results in more than one location, a list of locations will be displayed.
	 * If the query results in only one location, then a goto event will be fired(except for a 
	 * wildcard query in which case a list will still be displayed.
	 * 
	 * The listener will be notified after query and will indicate the query status.
	 * 
	 * @param fromAddr The address used to determine the scope of the query
	 * @param queryData the query input data
	 * @param listener the listener that will be notified when the query completes.
	 * @param monitor the task monitor
	 * @return true if the queryInput is found or appears to be a wildcard search.
	 */
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor);

	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor);

	public GoToOverrideService getOverrideService();

	public void setOverrideService(GoToOverrideService override);

	public Navigatable getDefaultNavigatable();

}
