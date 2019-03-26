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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

/**
 * Base abstract data type for a Dynamic structure data type that contains
 * some number of repeated data types.  The first entry contains the number of
 * repeated data types to follow.  Immediately following the first element are
 * the repeated data types.
 * 
 * The dynamic structure looks like this:
 * 
 *    RepeatDataType
 *       number = N   - two bytes, little endian
 *       RepDT1
 *       repDT2
 *       ...
 *       repDTN
 */
public abstract class RepeatCountDataType extends DynamicDataType {

	private DataType repeatDataType;

	protected RepeatCountDataType(DataType repeatDataType, CategoryPath path, String name,
			DataTypeManager dtm) {
		super(path, name, dtm);
		this.repeatDataType = repeatDataType;
	}

	/**
	 * @see ghidra.program.model.data.DynamicDataType#getAllComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		try {
			int n = (buf.getByte(0) & 0xff) * 16 + (buf.getByte(1) & 0xff) + 1;
			DataTypeComponent[] comps = new DataTypeComponent[n];
			comps[0] = new ReadOnlyDataTypeComponent(new WordDataType(), this, 2, 0, 0, "Size", "");
			int countSize = comps[0].getLength();
			int offset = countSize;
			MemoryBufferImpl newBuf = new MemoryBufferImpl(buf.getMemory(), buf.getAddress());
			newBuf.advance(countSize);
			for (int i = 1; i < n; i++) {
				DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(repeatDataType, newBuf);
				if (dti == null) {
					Msg.error(this, "ERROR: problem with data at " + newBuf.getAddress());
					return null;
				}
				int len = dti.getLength();
				comps[i] = new ReadOnlyDataTypeComponent(dti.getDataType(), this, len, i, offset);
				offset += len;
				newBuf.advance(len);
			}
			return comps;

		}
		catch (AddressOverflowException | AddressOutOfBoundsException | MemoryAccessException e) {
			Msg.error(this, "ERROR: problem with data at " + buf.getAddress());
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.program.model.data.Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

}
