/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.analysis;

import ghidra.app.util.query.AlignedObjectBasedPreviewTableModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

import java.util.List;

import docking.widgets.table.TableColumnDescriptor;

/**
 * 
 */
public class FindReferencesTableModel extends
		AlignedObjectBasedPreviewTableModel<ReferenceAddressPair> {

	private Address fromAddr;
	private AddressSetView fromAddressSet = null;

	public FindReferencesTableModel(Address fromAddr, ServiceProvider provider, Program prog) {
		super(fromAddr.toString(), provider, prog, null);
		this.fromAddr = fromAddr;
		setAlignment(prog.getLanguage().getInstructionAlignment());
	}

	public FindReferencesTableModel(AddressSetView fromAddresses, PluginTool tool, Program prog) {
		super("[ " + fromAddresses + " ]", tool, prog, null, true);
		this.fromAddressSet = fromAddresses;
		this.fromAddr = fromAddressSet.getMinAddress();
		setAlignment(prog.getLanguage().getInstructionAlignment());
	}

	@Override
	protected TableColumnDescriptor<ReferenceAddressPair> createTableColumnDescriptor() {
		TableColumnDescriptor<ReferenceAddressPair> descriptor =
			new TableColumnDescriptor<ReferenceAddressPair>();

		descriptor.addVisibleColumn(new ReferenceFromAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new ReferenceFromLabelTableColumn());
		descriptor.addVisibleColumn(new ReferenceFromPreviewTableColumn());
		descriptor.addVisibleColumn(new ReferenceToAddressTableColumn());
		descriptor.addVisibleColumn(new ReferenceToPreviewTableColumn());

		return descriptor;
	}

	@Override
	protected void initializeUnalignedList(Accumulator<ReferenceAddressPair> accumulator,
			TaskMonitor monitor) throws CancelledException {
		ProgramMemoryUtil.loadDirectReferenceList(getProgram(), alignment, fromAddr,
			fromAddressSet, accumulator, monitor);
	}

	AddressSetView getSearchAddressSet() {
		return fromAddressSet;
	}

	Address getAddress() {
		return fromAddr;
	}

	@Override
	public Address getAddress(int row) {
		ReferenceAddressPair refAddrPair = filteredData.get(row);
		return refAddrPair.getSource();
	}

	@Override
	public Address getAlignmentAddress(List<ReferenceAddressPair> data, int index) {
		ReferenceAddressPair refAddrPair = data.get(index);
		return refAddrPair.getSource();
	}
}
