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
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class EmptyListingModel implements ListingModel {
	@Override
	public void addListener(ListingModelListener listener) {
		// stub
	}

	@Override
	public Address getAddressAfter(Address address) {
		return null;
	}

	@Override
	public Address getAddressBefore(Address address) {
		return null;
	}

	@Override
	public AddressSetView getAddressSet() {
		return new AddressSet();
	}

	@Override
	public Layout getLayout(Address address, boolean isGapAddress) {
		return null;
	}

	@Override
	public int getMaxWidth() {
		return 0;
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public boolean isOpen(Data object) {
		return false;
	}

	@Override
	public void removeListener(ListingModelListener listener) {
		// stub
	}

	@Override
	public void toggleOpen(Data object) {
		// stub
	}

	@Override
	public void openAllData(Data data, TaskMonitor monitor) {
		// stub
	}

	@Override
	public void closeAllData(Data data, TaskMonitor monitor) {
		// stub
	}

	@Override
	public void closeData(Data data) {
		// stub
	}

	@Override
	public boolean openData(Data data) {
		return false;
	}

	@Override
	public void openAllData(AddressSetView addresses, TaskMonitor monitor) {
		// stub
	}

	@Override
	public void closeAllData(AddressSetView addresses, TaskMonitor monitor) {
		// stub
	}

	@Override
	public boolean isClosed() {
		return false;
	}

	@Override
	public void setFormatManager(FormatManager formatManager) {
		// stub
	}

	@Override
	public void dispose() {
		// stub
	}

	@Override
	public AddressSet adjustAddressSetToCodeUnitBoundaries(AddressSet addressSet) {
		return new AddressSet();
	}

	@Override
	public ListingModel copy() {
		return new EmptyListingModel();
	}
}
