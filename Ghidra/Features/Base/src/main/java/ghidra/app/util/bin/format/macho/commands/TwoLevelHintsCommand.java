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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a twolevel_hints_command structure 
 */
public class TwoLevelHintsCommand extends LoadCommand {
	private long offset;
	private long nhints;
	private List<TwoLevelHint> hints = new ArrayList<>();

	TwoLevelHintsCommand(BinaryReader reader) throws IOException {
		super(reader);
		offset = reader.readNextUnsignedInt();
		nhints = checkCount(reader.readNextUnsignedInt());

		long index = reader.getPointerIndex();
		reader.setPointerIndex(offset);
		for (long i = 0; i < nhints; ++i) {
			hints.add(new TwoLevelHint(reader));
		}
		reader.setPointerIndex(index);
	}

	public List<TwoLevelHint> getHints() {
		return hints;
	}

	/**
	 * Returns the offset to the hint table.
	 * @return the offset to the hint table
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the number of hints in the hint table.
	 * @return the number of hints in the hint table
	 */
	public long getNumberOfHints() {
		return nhints;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "offset", null);
		struct.add(DWORD, "nhints", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "twolevel_hints_command";
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			ProgramFragment fragment = createFragment(api, baseAddress, parentModule);
			Address addr = baseAddress.getNewAddress(getStartIndex());
			api.createData(addr, toDataType());

			Address hintStartAddress = baseAddress.add(getOffset());
			Address hintAddress = hintStartAddress;
			for (TwoLevelHint hint : hints) {
				if (monitor.isCancelled()) {
					return;
				}
				DataType hintDT = hint.toDataType();
				api.createData(hintAddress, hintDT);
				api.setPlateComment(hintAddress,
					"Sub-image Index: 0x" + Integer.toHexString(hint.getSubImageIndex()) +
						'\n' + "      TOC Index: 0x" +
						Integer.toHexString(hint.getTableOfContentsIndex()));
				hintAddress = hintAddress.add(hintDT.getLength());
			}
			fragment.move(hintStartAddress, hintAddress.subtract(1));
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}
}
