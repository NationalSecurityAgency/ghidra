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
package ghidra.feature.vt.gui.provider.functionassociation;

import java.util.*;

import docking.widgets.table.*;
import ghidra.feature.vt.api.db.DeletedMatch;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

class VTFunctionAssociationTableModel extends AddressBasedTableModel<VTFunctionRowObject> {

	static final String NAME_COL_NAME = "Name";
	static final String ADDRESS_COL_NAME = "Address";
	static final String PROTOTYPE_COL_NAME = "Prototype";

	static final int ADDRESS_COL_WIDTH = 50;

	static final int NAME_COL = 0;
	static final int ADDRESS_COL = 1;
	static final int PROTOTYPE_COL = 2;

	private static final String TITLE = "VTFunctionAssociation Table Model";

	private final VTController controller;
	private final boolean isSourceProgram;
	private FilterSettings filterSettings = FilterSettings.SHOW_ALL;

	VTFunctionAssociationTableModel(PluginTool tool, VTController controller, Program program,
			boolean isSourceProgram) {
		super(TITLE + (isSourceProgram ? " Source Program" : " Destination Program"), tool, program,
			null);
		this.controller = controller;
		this.isSourceProgram = isSourceProgram;
	}

	@Override
	protected TableColumnDescriptor<VTFunctionRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<VTFunctionRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionSignatureTableColumn()));

		return descriptor;
	}

	public int getKeyCount() {
		if (getProgram() == null) {
			return 0;
		}

		FunctionManager functionManager = getProgram().getFunctionManager();
		return functionManager.getFunctionCount();
	}

	private class FunctionKeyIterator implements LongIterator {
		private FunctionIterator itr;

		FunctionKeyIterator(FunctionManager functionMgr) {
			itr = functionMgr.getFunctions(true);
		}

		@Override
		public boolean hasNext() {
			if (itr == null) {
				return false;
			}
			return itr.hasNext();
		}

		@Override
		public long next() {
			Function function = itr.next();
			return function.getID();
		}

		@Override
		public boolean hasPrevious() {
			throw new UnsupportedOperationException();
		}

		@Override
		public long previous() {
			throw new UnsupportedOperationException();
		}
	}

	void functionAdded(Function function) {
		addObject(new VTFunctionRowObject(getInitializedFunctionInfo(function)));

		// assumption: added functions did not exist and thus could not have been the basis for
		//             a match.  Thus, we don't have to add the new function to the 
		//             collection of matched functions.
	}

	private FunctionAssociationInfo getInitializedFunctionInfo(Function function) {
		VTSession session = controller.getSession();
		VTAssociationManager associationManager = session.getAssociationManager();
		Collection<VTAssociation> associations = null;
		if (isSourceProgram) {
			associations =
				associationManager.getRelatedAssociationsBySourceAddress(function.getEntryPoint());
		}
		else {
			associations = associationManager.getRelatedAssociationsByDestinationAddress(
				function.getEntryPoint());

		}
		boolean isInAssociation = !associations.isEmpty();
		boolean isInAcceptedAssociation = containsAcceptedAssocation(associations);

		FunctionAssociationInfo info = new FunctionAssociationInfo(function.getID());
		info.setFilterData(isInAssociation, isInAcceptedAssociation);
		return info;
	}

	private boolean containsAcceptedAssocation(Collection<VTAssociation> associations) {
		for (VTAssociation vtAssociation : associations) {
			if (vtAssociation.getStatus() == VTAssociationStatus.ACCEPTED) {
				return true;
			}
		}
		return false;
	}

	void functionRemoved(Function function) {
		removeObject(new VTFunctionRowObject(new FunctionAssociationInfo(function.getID())));
	}

	void associationChanged(VTAssociation association) {
		Address address = null;
		if (isSourceProgram) {
			address = association.getSourceAddress();
		}
		else {
			address = association.getDestinationAddress();
		}

		FunctionManager functionManager = getProgram().getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		if (function == null) {
			return;
		}

		FunctionAssociationInfo info = getFunctionInfo(function);
		if (info == null) {
			return; // must have been removed; nothing to filter
		}
		info.setFilterData(true, association.getStatus() == VTAssociationStatus.ACCEPTED);
		reFilter();
	}

	void matchAdded(VTMatch match) {
		VTAssociation association = match.getAssociation();
		Address address = null;
		if (isSourceProgram) {
			address = association.getSourceAddress();
		}
		else {
			address = association.getDestinationAddress();
		}

		FunctionManager functionManager = getProgram().getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		if (function == null) {
			return;
		}

		FunctionAssociationInfo info = getFunctionInfo(function);
		if (info == null) {
			return; // must have been removed; nothing to filter
		}

		info.setFilterData(true, association.getStatus() == VTAssociationStatus.ACCEPTED);
		reFilter();
	}

	private FunctionAssociationInfo getFunctionInfo(Function function) {
		// find the existing info for the function ID - take advantage of the binary search feature
		// in the model.  Create an equivalent info to look up the real info.
		int index = getUnfilteredIndexForRowObject(
			new VTFunctionRowObject(new FunctionAssociationInfo(function.getID())));
		VTFunctionRowObject existingRowObject = getUnfilteredRowObjectForIndex(index);
		if (existingRowObject == null) {
			return null;
		}

		return existingRowObject.getInfo();
	}

	void matchRemoved(DeletedMatch match) {
		Address address = null;
		if (isSourceProgram) {
			address = match.getSourceAddress();
		}
		else {
			address = match.getDestinationAddress();
		}

		FunctionManager functionManager = getProgram().getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		if (function == null) {
			return;
		}

		FunctionAssociationInfo info = getFunctionInfo(function);
		if (info == null) {
			return; // must have been removed; nothing to filter
		}
		info.setFilterData(false, false);
		reFilter();
	}

	void clear() {
		clearData();
	}

	Function getFunction(int row) {
		VTFunctionRowObject rowObject = getRowObject(row);
		FunctionAssociationInfo info = rowObject.getInfo();
		Program program = getProgram();
		FunctionManager manager = program.getFunctionManager();
		return manager.getFunction(info.getFunctionID());
	}

	@Override
	public Address getAddress(int row) {
		Function function = getFunction(row);
		return function != null ? function.getEntryPoint() : null;
	}

	public void setFilterSettings(FilterSettings settings) {
		this.filterSettings = settings;
		reFilter();
	}

	@Override
	protected void doLoad(Accumulator<VTFunctionRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		LongIterator it = LongIterator.EMPTY;

		if (getProgram() != null) {
			FunctionManager functionManager = getProgram().getFunctionManager();
			it = new FunctionKeyIterator(functionManager);

			monitor.initialize(getKeyCount());
			while (it.hasNext()) {
				monitor.incrementProgress(1);
				monitor.checkCanceled();
				long key = it.next();

				Function f = functionManager.getFunction(key);
				if (!f.isThunk()) {
					accumulator.add(new VTFunctionRowObject(new FunctionAssociationInfo(key)));
				}
			}
		}

	}

	@Override
	public List<VTFunctionRowObject> doFilter(List<VTFunctionRowObject> data,
			TableSortingContext<VTFunctionRowObject> lastSortingContext, TaskMonitor monitor)
			throws CancelledException {

		if (data.size() == 0) {
			return data;
		}

		if (hasNoFilter()) {
			return data;
		}

		if (filterSettings != FilterSettings.SHOW_ALL) {
			initializeFilterData(data, monitor);
		}

		monitor.initialize(data.size());

		List<VTFunctionRowObject> filteredList = new ArrayList<>();
		for (int row = 0; row < data.size(); row++) {
			if (monitor.isCancelled()) {
				return filteredList; // canceled just return what has matches so far
			}

			monitor.incrementProgress(1);
			VTFunctionRowObject rowObject = data.get(row);
			FunctionAssociationInfo info = rowObject.getInfo();

			if (!passesUnmatchedFunctionFilter(info)) {
				continue;
			}

			if (rowMatchesFilters(row, rowObject, monitor)) {
				VTFunctionRowObject newObject = new VTFunctionRowObject(info);
				filteredList.add(newObject);
			}
		}

		return filteredList;
	}

	private boolean hasNoFilter() {
		return filterSettings == FilterSettings.SHOW_ALL && !hasFilter();
	}

	private boolean passesUnmatchedFunctionFilter(FunctionAssociationInfo info) {
		switch (filterSettings) {
			case SHOW_UNACCEPTED:
				return !info.isInAcceptedAssociation();
			case SHOW_UNMATCHED:
				return !info.isInAssociation();
			default:
				return true;
		}
	}

	private void initializeFilterData(List<VTFunctionRowObject> data, TaskMonitor monitor)
			throws CancelledException {
		VTSession session = controller.getSession();
		VTAssociationManager associationManager = session.getAssociationManager();

		monitor.setMessage("Loading matched functions...");
		monitor.initialize(associationManager.getAssociationCount());

		Set<Long> matchSet = new HashSet<>();
		Set<Long> acceptedSet = new HashSet<>();

		FunctionManager functionManager = getProgram().getFunctionManager();
		List<VTAssociation> associations = associationManager.getAssociations();
		for (VTAssociation association : associations) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Address functionAddress = null;
			if (isSourceProgram) {
				functionAddress = association.getSourceAddress();
			}
			else {
				functionAddress = association.getDestinationAddress();
			}

			Function function = functionManager.getFunctionAt(functionAddress);
			if (function != null) {
				Long functionID = function.getID();
				matchSet.add(functionID);
				if (association.getStatus() == VTAssociationStatus.ACCEPTED) {
					acceptedSet.add(functionID);
				}
			}
		}
		monitor.setMessage("Setting filter data...");
		monitor.initialize(data.size());
		for (int row = 0; row < data.size(); row++) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			VTFunctionRowObject rowObject = data.get(row);
			FunctionAssociationInfo info = rowObject.getInfo();
			Long functionID = info.getFunctionID();
			info.setFilterData(matchSet.contains(functionID), acceptedSet.contains(functionID));
		}

	}

	private boolean rowMatchesFilters(int row, VTFunctionRowObject rowObject, TaskMonitor monitor) {
		TableFilter<VTFunctionRowObject> tableFilter = getTableFilter();
		return tableFilter.acceptsRow(rowObject);
	}

}
