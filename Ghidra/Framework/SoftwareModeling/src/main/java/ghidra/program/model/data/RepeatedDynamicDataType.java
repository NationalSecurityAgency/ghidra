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
package ghidra.program.model.data;

import java.util.ArrayList;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.Conv;
import ghidra.util.Msg;

/**
 * Template for a repeated Dynamic Data Type.
 * 
 * Base abstract data type for a Dynamic structure data type that contains
 * some number of repeated data types.  After each data type, including the header
 * there is a terminator value which specifies whether there are any more data structures
 * following.  TerminatorValue can be 1,2,4,or 8 bytes.
 * 
 * The dynamic structure looks like this:
 * 
 *    RepeatDynamicDataType
 *       Header
 *       TerminatorV1
 *       RepDT1
 *       TerminatorV2
 *       RepDT2
 *       ...
 *       RepDTN-1
 *       TerminatorVN  == TerminateValue
 *       
 */
public abstract class RepeatedDynamicDataType extends DynamicDataType {

	protected String description;
	protected DataType header;
	protected DataType baseStruct;
	protected long terminatorValue;
	protected int terminatorSize;

	/**
	 * Construct Repeat Dynamic Data Type Template.
	 * 
	 * @param name            name of this data type
	 * @param description     description of the data type
	 * @param header          header data type
	 * @param baseStruct      repeated structure following the data type
	 * @param terminatorValue value to terminate repeats on
	 * @param terminatorSize  size of the value
	 */
	public RepeatedDynamicDataType(String name, String description, DataType header,
			DataType baseStruct, long terminatorValue, int terminatorSize, DataTypeManager dtm) {
		super(name, dtm);
		this.description = description;
		this.header = header;
		this.baseStruct = baseStruct;
		this.terminatorValue = terminatorValue;
		this.terminatorSize = terminatorSize;
	}

	/**
	 * @see ghidra.program.model.data.DynamicDataType#getAllComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Memory memory = buf.getMemory();
		ArrayList<DataTypeComponent> compList = new ArrayList<DataTypeComponent>();

		ReadOnlyDataTypeComponent comp;
		int countSize = 0;
		int ordinal = 0;
		if (header != null) {
			comp =
				new ReadOnlyDataTypeComponent(header, this, header.getLength(), ordinal, 0,
					header.getName() + "_" + buf.getAddress(), "");
			compList.add(ordinal++, comp);
			countSize = comp.getLength();
		}
		int offset = countSize;
		MemoryBufferImpl newBuf = new MemoryBufferImpl(memory, buf.getAddress());
		try {
			newBuf.advance(countSize);
			while (moreComponents(memory, newBuf.getAddress())) {
				DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(baseStruct, newBuf);
				if (dti == null) {
					Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
					return null;
				}
				int len = dti.getLength();
				comp =
					new ReadOnlyDataTypeComponent(dti.getDataType(), this, len, ordinal, offset,
						baseStruct.getName() + "_" + newBuf.getAddress(), "");
				compList.add(ordinal, comp);
				offset += len;
				newBuf.advance(len);
				ordinal++;
			}
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
			return null;
		}

		DataTypeComponent[] comps = new DataTypeComponent[compList.size()];
		for (int i = 0; i < compList.size(); i++) {
			comps[i] = compList.get(i);
		}
		return comps;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	public String getMnemonic(Settings settings) {
		return name;
	}

	private boolean moreComponents(Memory memory, Address loc) {
		long test = 0;
		try {
			switch (terminatorSize) {
				case 1:
					test = Conv.byteToLong(memory.getByte(loc));
					break;
				case 2:
					test = Conv.shortToLong(memory.getShort(loc));
					break;
				case 4:
					test = Conv.intToLong(memory.getInt(loc));
					break;
				case 8:
					test = memory.getLong(loc);
					break;
				default:
					for (int i = 0; i < terminatorSize; i++) {
						test = memory.getByte(loc);
						if (test != terminatorValue) {
							return true;
						}
					}
					return false;
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		return (test != terminatorValue);
	}

}
