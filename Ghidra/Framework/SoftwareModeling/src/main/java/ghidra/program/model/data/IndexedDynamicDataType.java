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

import java.util.Hashtable;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.Conv;
import ghidra.util.Msg;

/**
 * Indexed Dynamic Data Type template.  Used to create instances of the data type at
 * a given location in memory based on the data found there.
 * 
 * This data struture is used when there is a structure with key field in a header.
 * The key field, which is a number, sets which of a number of structures follows the header.
 * 
 *     Header
 *        field a
 *        field b
 *        keyfield (value 1 means struct1 follows
 *                  value 2 means struct2 follows
 *                  .....
 *                  value n means structN follows
 *     Struct1 | Struct2 | ..... | StructN
 */
public abstract class IndexedDynamicDataType extends DynamicDataType {

	/**
	 * Structures which do not have a body  
	 */
	public static final String NULL_BODY_DESCRIPTION = "NullBody";

	protected String description;
	protected DataType header;
	protected long[] keys;
	protected DataType[] structs;
	protected long indexOffset;
	protected int indexSize;
	protected long mask;

	private Hashtable<Long, Integer> table = new Hashtable<Long, Integer>();

	/**
	 * Construct and the Index dynamic data type template.
	 * 
	 * @param name        name of the data type
	 * @param description description of the data type
	 * @param header      the header data type that holds the keys to the location of other data types
	 * @param keys        key value array, one to one mapping to structs array
	 * @param structs     structure[n] to use if the key value equals keys[n]
	 * @param indexOffset index into the header structure that holds the key value
	 * @param indexSize   size of the key value in bytes
	 * @param mask        mask used on the key value to get the final key
	 */
	public IndexedDynamicDataType(String name, String description, DataType header, long[] keys,
			DataType[] structs, long indexOffset, int indexSize, long mask, DataTypeManager dtm) {
		super(name, dtm);
		this.description = description;
		this.header = header;
		this.keys = keys;
		this.structs = structs;
		this.indexOffset = indexOffset;
		this.indexSize = indexSize;
		this.mask = mask;

		if (keys.length != structs.length) {
			Msg.error(this, "ERROR: keys.length must equal structs.length");
			return;
		}

		for (int i = 0; i < keys.length; i++) {
			table.put(new Long(keys[i]), new Integer(i));
		}
		if (mask == 0) {
			mask = 0xFFFFFFFF;
		}
	}

	/**
	 * Construct the Indexed dynamic data type template.
	 * Used when there is one of two structures following and a single value tells which one.
	 * If the key value in the header structure matches the singleKey, then the first structure is used.
	 * If the key value does not match the singleKey, then the second structure is used.
	 * 
	 * @param name        name of the data type
	 * @param description description of the data type
	 * @param header      the header data type that holds the keys to the location of other data types
	 * @param singleKey   A single key value selects whether the structure appears
	 *                    If the key value equals the singleKey then the first structure is used
	 *                    If the key value doesn't, the second structure is used
	 * @param structs     structure[n] to use if the key value equals keys[n]
	 * @param indexOffset index into the header structure that holds the key value
	 * @param indexSize   size of the key value in bytes
	 * @param mask        mask used on the key value to get the final key
	 */
	public IndexedDynamicDataType(String name, String description, DataType header, long singleKey,
			DataType[] structs, long indexOffset, int indexSize, long mask, DataTypeManager dtm) {
		super(name, dtm);
		this.name = name;
		this.description = description;
		this.header = header;
		this.keys = new long[] { singleKey };
		this.structs = structs;
		this.indexOffset = indexOffset;
		this.indexSize = indexSize;
		this.mask = mask == 0 ? 0xFFFFFFFF : mask;

		if (structs.length > 2) {
			Msg.warn(
				this,
				"WARNING: IndexedDynamicDataType constructed using single key -- only first two structures will be used");
		}

		for (int i = 0; i < structs.length; i++) {
			table.put(new Long(i), new Integer(i));
		}
	}

	/**
	 * @see ghidra.program.model.data.DynamicDataType#getAllComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Memory memory = buf.getMemory();
		Address start = buf.getAddress();

		// Find index
		long index = getIndex(memory, start.add(indexOffset)) & mask;
		Integer structIndex = null;
		if (keys.length == 1) {
			structIndex = (index == keys[0]) ? new Integer(0) : new Integer(1);
		}
		else {
			structIndex = table.get(new Long(index));
		}

		if (structIndex == null) {
			Msg.error(this, "ERROR in " + name + " at " + start);
			return null;
		}
		DataType data = structs[structIndex.intValue()];

		if (data == null) {
			Msg.error(this, "ERROR in " + name + " at " + start);
			return null;
		}
		DataTypeComponent[] comps = null;
		if (data.getDescription().equalsIgnoreCase(NULL_BODY_DESCRIPTION)) {
			comps = new DataTypeComponent[1];
		}
		else {
			comps = new DataTypeComponent[2];
		}
		MemoryBufferImpl newBuf = new MemoryBufferImpl(memory, buf.getAddress());
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(header, newBuf);
		if (dti == null) {
			Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
			return null;
		}
		int len = dti.getLength();
		comps[0] =
			new ReadOnlyDataTypeComponent(header, this, len, 0, 0, dti.getDataType().getName(), "");
		if (comps.length > 1) {
			try {
				int countSize = len;
				int offset = countSize;
				newBuf = new MemoryBufferImpl(memory, buf.getAddress());
				newBuf.advance(countSize);
				dti = DataTypeInstance.getDataTypeInstance(data, newBuf);
				if (dti == null) {
					Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
					return null;
				}
				len = dti.getLength();
				comps[1] =
					new ReadOnlyDataTypeComponent(dti.getDataType(), this, len, 1, offset,
						dti.getDataType().getName() + "_" + newBuf.getAddress(), "");
				//name = dti.getDataType().getName();
			}
			catch (AddressOverflowException e) {
				Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
				return null;
			}
		}
		return comps;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return description;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
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

	private long getIndex(Memory memory, Address loc) {
		long test = 0;
		try {
			switch (indexSize) {
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

		return test;
	}
}
