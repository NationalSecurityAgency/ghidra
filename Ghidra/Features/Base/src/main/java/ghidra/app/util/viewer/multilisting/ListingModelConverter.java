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
package ghidra.app.util.viewer.multilisting;

import docking.widgets.fieldpanel.Layout;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.listingpanel.ListingModelListener;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DiffUtility;
import ghidra.program.util.SimpleDiffUtility;
import ghidra.util.task.TaskMonitor;

public class ListingModelConverter implements ListingModel {

	private ListingModel primaryModel;
	private ListingModel model;
	private Program primaryProgram;
	private Program program;
	private AddressTranslator translator;

	/**
	 * Converts addresses from the primary model into addresses for this converters model.
	 * @param primaryModel the primary model
	 * @param model this converter's model
	 */
	public ListingModelConverter(ListingModel primaryModel, ListingModel model) {
		this.primaryModel = primaryModel;
		this.model = model;
		this.primaryProgram = primaryModel.getProgram();
		this.program = model.getProgram();
	}

	@Override
	public void addListener(ListingModelListener listener) {
		model.addListener(listener);
	}

	@Override
	public void dispose() {
		model.dispose();
	}

	@Override
	/**
	 * Convert the address from the primary model to the model for this converter and return 
	 * this model's address that comes after it.
	 * @param primaryModelAddress the address from the primary model
	 * @return the address that comes after it in this converter's model (the non-primary model).
	 */
	public Address getAddressAfter(Address primaryModelAddress) {
		Address addr = getConvertedAddress(primaryModelAddress);
		Address retAddr = (addr != null) ? model.getAddressAfter(addr) : null;
		if (retAddr == null) {
			Address addressBefore = primaryModel.getAddressAfter(primaryModelAddress);
			retAddr =
				SimpleDiffUtility.getCompatibleAddress(primaryProgram, addressBefore, program);
		}
		return retAddr;
	}

	@Override
	/**
	 * Convert the address from the primary model to the model for this converter and return 
	 * this model's address that comes before it.
	 * @param primaryModelAddress the address from the primary model
	 * @return the address that comes before it in this converter's model (the non-primary model).
	 */
	public Address getAddressBefore(Address primaryModelAddress) {
		Address addr = getConvertedAddress(primaryModelAddress);
		Address retAddr = (addr != null) ? model.getAddressBefore(addr) : null;
		if (retAddr == null) {
			Address addressBefore = primaryModel.getAddressBefore(primaryModelAddress);
			retAddr =
				SimpleDiffUtility.getCompatibleAddress(primaryProgram, addressBefore, program);
		}
		return retAddr;
	}

	@Override
	public AddressSetView getAddressSet() {
		AddressSetView addressSet = primaryModel.getAddressSet();
		return DiffUtility.getCompatibleAddressSet(addressSet, program);
	}

	@Override
	public Layout getLayout(Address primaryAddress, boolean isGapAddress) {
		Address addr = getConvertedAddress(primaryAddress);
		if (addr == null) {
			return null;
		}
		return model.getLayout(addr, isGapAddress);
	}

	private Address getConvertedAddress(Address primaryAddress) {
		return (translator != null) ? translator.translate(primaryAddress, primaryProgram, program)
				: SimpleDiffUtility.getCompatibleAddress(primaryProgram, primaryAddress, program);
	}

	@Override
	public int getMaxWidth() {
		return model.getMaxWidth();
	}

	@Override
	public Program getProgram() {
		return model.getProgram();
	}

	@Override
	public boolean isClosed() {
		return model.isClosed();
	}

	@Override
	public boolean isOpen(Data data) {
		return model.isOpen(data);
	}

	@Override
	public boolean openData(Data data) {
		return model.openData(data);
	}

	@Override
	public void openAllData(Data data, TaskMonitor monitor) {
		model.openAllData(data, null);
	}

	@Override
	public void openAllData(AddressSetView addresses, TaskMonitor monitor) {
		model.openAllData(addresses, monitor);
	}

	@Override
	public void closeData(Data data) {
		model.closeData(data);
	}

	@Override
	public void closeAllData(Data data, TaskMonitor monitor) {
		model.closeAllData(data, null);
	}

	@Override
	public void closeAllData(AddressSetView addresses, TaskMonitor monitor) {
		model.closeAllData(addresses, monitor);
	}

	@Override
	public void removeListener(ListingModelListener listener) {
		model.removeListener(listener);
	}

	@Override
	public void setFormatManager(FormatManager formatManager) {
		model.setFormatManager(formatManager);
	}

	@Override
	public void toggleOpen(Data data) {
		model.toggleOpen(data);
	}

	@Override
	public AddressSet adjustAddressSetToCodeUnitBoundaries(AddressSet addressSet) {
		AddressSet compatibleAddressSet = DiffUtility.getCompatibleAddressSet(addressSet, program);
		return model.adjustAddressSetToCodeUnitBoundaries(compatibleAddressSet);
	}

	/**
	 * Sets an address translator for this converter. If provided the translator converts
	 * addresses from the primary program to those in the program for this converter's model.
	 * @param translator translates addresses between the primary model and this converter's model
	 */
	public void setAddressTranslator(AddressTranslator translator) {
		this.translator = translator;
	}

	@Override
	public ListingModel copy() {
		return new ListingModelConverter(primaryModel.copy(), model.copy());
	}

}
