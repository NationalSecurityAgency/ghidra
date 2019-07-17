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
package ghidra.app.plugin.core.function.editor;

import java.util.*;

import javax.swing.SwingUtilities;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

class StorageAddressModel {

	private List<VarnodeInfo> varnodes = new ArrayList<>();
	private int requiredSize;
	private boolean unconstrained;
	private int[] selectedVarnodeRows = new int[0];
	private ModelChangeListener listener;
	private String statusText;
	private boolean isValid;
	private Program program;

	StorageAddressModel(Program program, VariableStorage storage, ModelChangeListener listener) {

		this.listener = listener;
		this.program = program;

		if (storage != null) {
			for (Varnode varnode : storage.getVarnodes()) {
				varnodes.add(new VarnodeInfo(program, varnode));
			}
		}
		validate();
	}

	void addVarnode() {
		listener.tableRowsChanged();
		varnodes.add(new VarnodeInfo(program, VarnodeType.Register));
		setSelectedRow(varnodes.size() - 1);
		notifyDataChanged();
	}

	void removeVarnodes() {
		if (!canRemoveVarnodes()) {
			throw new AssertException("Attempted to remove varnodes when not allowed.");
		}
		listener.tableRowsChanged();
		Arrays.sort(selectedVarnodeRows);
		for (int i = selectedVarnodeRows.length - 1; i >= 0; i--) {
			int index = selectedVarnodeRows[i];
			varnodes.remove(index);
		}
		if (varnodes.isEmpty()) {
			selectedVarnodeRows = new int[0];
		}
		else {
			int selectRow = Math.min(selectedVarnodeRows[0], varnodes.size() - 1);
			selectedVarnodeRows = new int[] { selectRow };
		}
		notifyDataChanged();
	}

	void moveSelectedVarnodeUp() {
		if (!canMoveVarnodeUp()) {
			throw new AssertException("Attempted to move a varnode up when not allowed.");
		}
		listener.tableRowsChanged();
		int index = selectedVarnodeRows[0];
		VarnodeInfo info = varnodes.remove(index);
		varnodes.add(index - 1, info);
		setSelectedRow(index - 1);
		notifyDataChanged();
	}

	void moveSelectedVarnodeDown() {
		if (!canMoveVarnodeDown()) {
			throw new AssertException("Attempted to move a parameter down when not allowed.");
		}
		listener.tableRowsChanged();

		int index = selectedVarnodeRows[0];
		VarnodeInfo info = varnodes.remove(index);
		varnodes.add(index + 1, info);
		setSelectedRow(index + 1);
		notifyDataChanged();
	}

	List<VarnodeInfo> getVarnodes() {
		return varnodes;
	}

	void setRequiredSize(int requiredSize, boolean unconstrained) {
		this.requiredSize = requiredSize;
		this.unconstrained = unconstrained;
		validate();
	}

	int getRequiredSize() {
		return requiredSize;
	}

	boolean isUnconstrained() {
		return unconstrained;
	}

	int getCurrentSize() {
		int size = 0;
		for (VarnodeInfo varnode : varnodes) {
			if (varnode.getSize() != null) {
				size += varnode.getSize();
			}
		}
		return size;
	}

	String getStatusText() {
		return statusText;
	}

	boolean isValid() {
		return isValid;
	}

	void setSelectedVarnodeRows(int[] selectedRows) {
		selectedVarnodeRows = selectedRows;
		notifyDataChanged();
	}

	private void setSelectedRow(int row) {
		selectedVarnodeRows = new int[] { row };
	}

	int[] getSelectedVarnodeRows() {
		return selectedVarnodeRows;
	}

	void notifyDataChanged() {
		validate();

		SwingUtilities.invokeLater(() -> listener.dataChanged());
	}

	private void validate() {
		statusText = "";
		isValid = hasValidVarnodes() && hasCorrectAllocatedSize() && isProperMix() && hasNoDups();
	}

	private boolean hasNoDups() {
		AddressSet addressSet = new AddressSet();
		for (int i = 0; i < varnodes.size(); i++) {
			VarnodeInfo varnode = varnodes.get(i);
			AddressRange range;
			try {
				range = new AddressRangeImpl(varnode.getAddress(), varnode.getSize());
			}
			catch (AddressOverflowException e) {
				// should already have been checked
				throw new AssertException("Unexpected exception", e);
			}
			if (addressSet.intersects(range.getMinAddress(), range.getMaxAddress())) {
				statusText = "Row " + i + ": Overlapping storage address used.";
				return false;
			}
			addressSet.add(range);
		}
		return true;
	}

	private boolean isProperMix() {
		// all except last varnode must be a register
		for (int i = 0; i < varnodes.size() - 1; i++) {
			VarnodeInfo varnode = varnodes.get(i);
			if (varnode.getType() != VarnodeType.Register) {
				statusText = "Only the last entry may be of type " + varnode.getType();
				return false;
			}
		}
		return true;
	}

	private boolean hasCorrectAllocatedSize() {
		int currentSize = getCurrentSize();
		if (currentSize == 0) {
			statusText = "No storage has been allocated";
//			return false;
		}
		else if (currentSize > 0 && unconstrained) {
			return true;
		}
		else if (currentSize < requiredSize) {
			statusText = "Warning: Not enough storage space allocated";
//			return false;
		}
		else if (currentSize > requiredSize) {
			statusText = "Warning: Too much storage space allocated";
//			return false;
		}
		return true;
	}

	private boolean hasValidVarnodes() {
		for (int i = 0; i < varnodes.size(); i++) {
			VarnodeInfo varnode = varnodes.get(i);
			if (!(isValidSize(varnode, i) && isValidAddress(varnode, i))) {
				return false;
			}
		}
		return true;
	}

	private boolean isValidSize(VarnodeInfo varnode, int row) {
		Integer size = varnode.getSize();
		if (size == null) {
			statusText = "Row " + row + ": No size specified";
			return false;
		}
		if (size.intValue() <= 0) {
			statusText = "Row " + row + ": Size must be > 0";
			return false;
		}
		return true;
	}

	private boolean isValidAddress(VarnodeInfo varnode, int row) {
		Address address = varnode.getAddress();
		if (address == null) {
			statusText = "Row " + row + ": Invalid Varnode Address";
			return false;
		}
		try {
			new AddressRangeImpl(address, varnode.getSize());
		}
		catch (AddressOverflowException e) {
			statusText = "Row " + row + ": Varnode wraps within " +
				address.getAddressSpace().getName() + " space.";
			return false;
		}
		if (address.isStackAddress()) {
			long stackOffset = address.getOffset();
			if (stackOffset < 0 && -stackOffset < varnode.getSize()) {
				// do not allow stack varnode to span the 0-offset 
				// i.e., maintain separation of locals and params
				statusText = "Row " + row + ": Stack varnode spans 0 offset";
				return false;
			}
			return true;
		}
		Register register = program.getRegister(address, varnode.getSize());
		if (register == null) {
			Register register2 = program.getRegister(address);
			if (register2 != null) {
				statusText = "Row " + row + ": Register (size=" + (register2.getBitLength() / 8) +
					") too small for specified size(" + varnode.getSize() + ")";
			}
			else if (address.isRegisterAddress()) {
				statusText = "Row " + row + ": Invalid Register";
				return false;
			}
			return address.isMemoryAddress();
		}
		return true; // is register
	}

	boolean canRemoveVarnodes() {
		return selectedVarnodeRows.length > 0; // && selectedVarnodeRows.length < varnodes.size();
	}

	boolean canMoveVarnodeUp() {
		return selectedVarnodeRows.length == 1 && selectedVarnodeRows[0] > 0;
	}

	boolean canMoveVarnodeDown() {
		return selectedVarnodeRows.length == 1 && selectedVarnodeRows[0] < varnodes.size() - 1;
	}

	void setVarnodeType(VarnodeInfo varnode, VarnodeType type) {
		if (type == varnode.getType()) {
			return;
		}
		varnode.setVarnodeType(type);
		notifyDataChanged();
	}

	void setVarnode(VarnodeInfo info, String registerName) {
		Register register = program.getRegister(registerName);
		if (register != null) {
			setVarnode(info, register);
		}
	}

	void setVarnode(VarnodeInfo info, Register reg) {
		Address addr = reg.getAddress();
		int size;
		int currentSize = getCurrentSize();
		int regSize = reg.getBitLength() / 8;
		if (unconstrained) {
			setVarnode(info, addr, regSize);
			return;
		}
		Integer curVarnodeSize = info.getSize();
		if (reg.hasChildren() || curVarnodeSize == null || regSize < curVarnodeSize ||
			currentSize < requiredSize) {
			size = reg.getBitLength() / 8;
			if (curVarnodeSize != null) {
				currentSize -= curVarnodeSize;
			}
			if (currentSize < requiredSize) {
				size = Math.min(size, requiredSize - currentSize);
			}
		}
		else {
			size = curVarnodeSize;
		}
		if (reg.isBigEndian()) {
			// adjust address for big endian register
			int s = Math.min(reg.getMinimumByteSize(), size);
			addr = addr.add(reg.getMinimumByteSize() - s);
		}
		setVarnode(info, addr, size);

	}

	void setVarnode(VarnodeInfo info, Address address, Integer size) {
		if (SystemUtilities.isEqual(info.getAddress(), address) &&
			SystemUtilities.isEqual(info.getSize(), size)) {
			return;
		}
		info.setVarnode(address, size);
		notifyDataChanged();
	}

	Program getProgram() {
		return program;
	}

	VariableStorage getStorage() {
		if (!isValid) {
			return null;
		}
		if (varnodes.size() == 0) {
			if (requiredSize == 0) {
				return VariableStorage.VOID_STORAGE;
			}
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		List<Varnode> varnodeList = new ArrayList<>(varnodes.size());
		for (VarnodeInfo varnodeInfo : varnodes) {
			varnodeList.add(new Varnode(varnodeInfo.getAddress(), varnodeInfo.getSize()));
		}
		try {
			return new VariableStorage(program, varnodeList);
		}
		catch (InvalidInputException e) {
			// validation checks should prevent this.
			throw new AssertException("Unexpected exception", e);
		}
	}
}
