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

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.Conv;
import ghidra.util.Msg;

/**
 * A dynamic data type that changes the number of elements it contains based on a count found in
 * header data type.
 * The data type has a header data type which will contain the number of base data types following
 * the header data type.
 * 
 * NOTE: This is a special Dynamic data-type which can only appear as a component
 * created by a Dynamic data-type
 */
public abstract class CountedDynamicDataType extends DynamicDataType {

	private String description;
	private DataType header;
	private DataType baseStruct;
	private long counterOffset;
	private int counterSize;
	private long mask;

	/**
	 * Constructor for this dynamic data type builder.
	 * 
	 * @param name name of this dynamic data type
	 * @param description description of the data type
	 * @param header header data type that will contain the number of following elements
	 * @param baseStruct base data type for each of the following elements
	 * @param counterOffset offset of the number of following elements from the start of the header
	 * @param counterSize size of the count in bytes
	 * @param mask mask to apply to the count value to get the actual number of following elements.
	 */
	public CountedDynamicDataType(String name, String description, DataType header,
			DataType baseStruct, long counterOffset, int counterSize, long mask) {
		super(name, baseStruct.getDataTypeManager());
		this.description = description;
		this.header = header;
		this.baseStruct = baseStruct;
		this.counterOffset = counterOffset;
		this.counterSize = counterSize;
		this.mask = mask == 0 ? 0xFFFFFFFF : mask;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return this;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DynamicDataType#getAllComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Memory memory = buf.getMemory();
		Address start = buf.getAddress();

		// Find count
		int n = (int) getCount(memory, start.add(counterOffset));

		DataTypeComponent[] comps = new DataTypeComponent[n + 1];
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(header, buf);

		if (dti == null) {
			Msg.error(this, "ERROR: problem with data at " + buf.getAddress());
			return null;
		}
		int countSize = dti.getLength();
		comps[0] =
			new ReadOnlyDataTypeComponent(dti.getDataType(), this, countSize, 0, 0,
				header.getName() + "_" + buf.getAddress(), "");
		int offset = countSize;
		MemoryBufferImpl newBuf = new MemoryBufferImpl(memory, buf.getAddress());
		try {
			newBuf.advance(countSize);
			for (int i = 1; i <= n; i++) {
				dti = DataTypeInstance.getDataTypeInstance(baseStruct, buf);
				if (dti == null) {
					Msg.error(this, "ERROR: problem with data at " + buf.getAddress());
					return null;
				}
				int len = dti.getLength();
				comps[i] = new ReadOnlyDataTypeComponent(dti.getDataType(), this, len, i, offset,
					baseStruct.getName() + "_" + newBuf.getAddress(), "");
				offset += len;
				newBuf.advance(len);
			}
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "ERROR: problem with data at " + buf.getAddress());
			return null;
		}
		return comps;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return description;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.program.model.data.Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	/**
	 * Extract the size of the data type from the given location in memory
	 * 
	 * @param memory the memory to get the size from
	 * @param loc the address in memory where the size is located
	 * @return the size
	 */
	private long getCount(Memory memory, Address loc) {
		long test = 0;
		try {
			switch (counterSize) {
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
					return 0;
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		return test & mask;
	}

}
