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
package ghidra.app.util.viewer.listingpanel;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Model displaying program data in a {@link FieldPanel}
 */
public interface ListingModel {

	static final String FUNCTION_POINTER_OPTION_GROUP_NAME = "Function Pointers";

	public static final String DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME =
		FUNCTION_POINTER_OPTION_GROUP_NAME + Options.DELIMITER +
			"Display External Function Pointer Header";
	public static final String DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME =
		FUNCTION_POINTER_OPTION_GROUP_NAME + Options.DELIMITER +
			"Display Non-External Function Pointer Header";

	/**
	 * {@return the address set of all addresses in the model}
	 */
	public AddressSetView getAddressSet();

	/**
	 * Returns the next address that has displayable information after the given address. This 
	 * allows the listing to efficiently skip over large sections of undisplayable addresses such
	 * as those consumed by large data or addresses part of a closed function.
	 * @param address the address from which to find the next address with displayable information
	 * @return the next address with displayable information
	 */
	public Address getAddressAfter(Address address);

	/**
	 * Returns the previous address that has displayable information before the given address. This 
	 * allows the listing to efficiently skip over large sections of undisplayable addresses such
	 * as those consumed by large data or addresses part of a closed function.
	 * @param address the address from which to find the previous address with displayable
	 * information
	 * @return the previous address with displayable information
	 */
	public Address getAddressBefore(Address address);

	/**
	 * Returns a layout with displayable information for the given address.
	 * @param address the address to get displayable information
	 * @param isGapAddress true implies there is a gap of missing addresses before this address.
	 * Note that this is different from addresses that are hidden due to collapsed functions or
	 * closed data. These gaps are not even in consideration to display information such as
	 * undefined memory or a fragmented program view.
	 * @return a Layout with information to be displayed for the given address.
	 */
	public Layout getLayout(Address address, boolean isGapAddress);

	/**
	 * {@return the width of the longest layout this model can produce.}
	 */
	public int getMaxWidth();

	/**
	 * Returns true if the data is open
	 * 
	 * @param data the data to check
	 * @return true if the data is open
	 */
	public boolean isOpen(Data data);

	/**
	 * Changes the open state of the given data (open -&gt; closes; closed-&gt; open).
	 * 
	 * @param data the data to open
	 */
	public void toggleOpen(Data data);

	/**
	 * Sets whether or not to display function variables for the function at the given address.
	 * @param FunctionAddress the address of the function
	 * @param open if true, the variables are displayed, otherwise they are hidden
	 */
	public void setFunctionVariablesOpen(Address FunctionAddress, boolean open);

	/**
	 * Checks if the function variables are being displayed at the given address
	 * @param FunctionAddress the address of the function
	 * @return true if the variables are being displayed for the function at the given address
	 */
	public boolean areFunctionVariablesOpen(Address FunctionAddress);

	/**
	 * Sets the display of variables for all functions.  This basically sets the default state, 
	 * but the state can be overridden for individual functions. Changing this value erases all
	 * individually set values.
	 * @param open if true, show function variables
	 */
	public void setAllFunctionVariablesOpen(boolean open);

	/**
	 * Opens the given data, but not any sub-components.
	 * 
	 * @param data the data to open
	 * @return true if the data was opened (will return false if the data is already open or has no children)
	 */
	public boolean openData(Data data);

	/**
	 * Recursively open the given data and its sub-components.
	 * 
	 * @param data the data to open
	 * @param monitor the task monitor
	 */
	public void openAllData(Data data, TaskMonitor monitor);

	/**
	 * Opens all data found within the given addresses.  Each data is fully opened.
	 * 
	 * @param addresses the range of addresses to search for data
	 * @param monitor the task monitor
	 */
	public void openAllData(AddressSetView addresses, TaskMonitor monitor);

	/**
	 * Closes the given data, but not any sub-components.
	 * 
	 * @param data the data to close
	 */
	public void closeData(Data data);

	/**
	 * Recursively close the given data and its sub-components.
	 * 
	 * @param data the data to close
	 * @param monitor the task monitor
	 */
	public void closeAllData(Data data, TaskMonitor monitor);

	/**
	 * Closes all data found within the given addresses.  Each data is fully closed.
	 * 
	 * @param addresses the range of addresses to search for data
	 * @param monitor the task monitor
	 */
	public void closeAllData(AddressSetView addresses, TaskMonitor monitor);

	/**
	 * Adds a listener for changes to this model.
	 * @param listener the listener to be notified
	 */
	public void addListener(ListingModelListener listener);

	/**
	 * Removes a listener from those being notified of model changes.
	 * @param listener the listener to be removed
	 */
	public void removeListener(ListingModelListener listener);

	/**
	 * {@return the program being displayed by this model.}
	 */
	public Program getProgram();

	/**
	 * {@return true if the program being displayed by this listing has been closed (and therefor
	 * the model is invalid.)}
	 */
	public boolean isClosed();

	/**
	 * Sets the {@link FormatManager} for this model which determines the layout of the fields.
	 * @param formatManager the new FormatManager to use
	 */
	public void setFormatManager(FormatManager formatManager);

	/**
	 * Disposes this model
	 */
	public void dispose();

	/**
	 * Adjusts each range in the given address set to be on code unit boundaries.
	 * @param addressSet the address set to be adjusted
	 * @return a new AddressSet where each range is on a code unit boundary
	 */
	public AddressSet adjustAddressSetToCodeUnitBoundaries(AddressSet addressSet);

	/**
	 * Makes a copy of this model.
	 * @return a copy of this model.
	 */
	public ListingModel copy();

	/**
	 * Checks if the function at the given entry point is open or not.
	 * @param functionAddress the entry point of the function to check for open
	 * @return true if the function is open; false otherwise
	 */
	public boolean isFunctionOpen(Address functionAddress);

	/**
	 * Sets the function at the given address to be open or not
	 * @param functionAddress the entry point of the function to set open or closed
	 * @param open true to open the function, false to close it
	 */
	public void setFunctionOpen(Address functionAddress, boolean open);

	/**
	 * Sets all functions to open or closed.
	 * @param open if true, opens all function; otherwise closes all functions
	 */
	public void setAllFunctionsOpen(boolean open);
}
