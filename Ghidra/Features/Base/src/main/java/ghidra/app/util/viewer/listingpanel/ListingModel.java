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

import docking.widgets.fieldpanel.Layout;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public interface ListingModel {

	static final String FUNCTION_POINTER_OPTION_GROUP_NAME = "Function Pointers";

	public static final String DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME =
		FUNCTION_POINTER_OPTION_GROUP_NAME + Options.DELIMITER +
			"Display External Function Pointer Header";
	public static final String DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME =
		FUNCTION_POINTER_OPTION_GROUP_NAME + Options.DELIMITER +
			"Display Non-External Function Pointer Header";

	public AddressSetView getAddressSet();

	public Address getAddressAfter(Address address);

	public Address getAddressBefore(Address address);

	public Layout getLayout(Address address, boolean isGapAddress);

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

	public void addListener(ListingModelListener listener);

	public void removeListener(ListingModelListener listener);

	public Program getProgram();

	public boolean isClosed();

	public void setFormatManager(FormatManager formatManager);

	public void dispose();

	public AddressSet adjustAddressSetToCodeUnitBoundaries(AddressSet addressSet);

	/**
	 * Makes a copy of this model.
	 * @return a copy of this model.
	 */
	public ListingModel copy();
}
