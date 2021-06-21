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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.SignedLeb128DataType;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.WrappedMemBuffer;
import ghidra.util.Msg;

/**
 * <code>AndroidElfRelocationTableDataType</code> provides an implementation of 
 * an Android APS2 packed ELF relocation table.
 */
public class AndroidElfRelocationTableDataType extends DynamicDataType {

	public AndroidElfRelocationTableDataType() {
		this(null);
	}

	public AndroidElfRelocationTableDataType(DataTypeManager dtm) {
		super(CategoryPath.ROOT, "AndroidElfRelocationTable", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == dataMgr) {
			return this;
		}
		return new AndroidElfRelocationTableDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "Android Packed Relocation Table for ELF";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	static class LEB128Info {

		final int offset;
		final long value;
		final int byteLength;

		private LEB128Info(int offset, long value, int byteLength) {
			this.offset = offset;
			this.value = value;
			this.byteLength = byteLength;
		}

		DataTypeComponent getComponent(DynamicDataType parent, int ordinal, String name,
				String comment, long relocOffset) {
			return new ReadOnlyDataTypeComponent(
				new AndroidElfRelocationData(parent.getDataTypeManager(), relocOffset), parent,
				byteLength, ordinal, offset, name, comment);
		}

		DataTypeComponent getComponent(DynamicDataType parent, int ordinal, String name,
				String comment) {
			return new ReadOnlyDataTypeComponent(
				new SignedLeb128DataType(parent.getDataTypeManager()), parent, byteLength, ordinal,
				offset, name, comment);
		}

		static LEB128Info parse(BinaryReader reader, boolean signed) throws IOException {
			long nextPos = reader.getPointerIndex();
			long value = LEB128.readAsLong(reader, signed);
			long pos = reader.getPointerIndex();
			int size = (int) (pos - nextPos);
			return new LEB128Info((int) nextPos, value, size);
		}
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {

		try {
			byte[] bytes = new byte[4];
			if (buf.getBytes(bytes, 0) != 4 || !"APS2".equals(new String(bytes))) {
				return null;
			}

			ByteProvider provider = new MemBufferByteProvider(buf);
			BinaryReader reader = new BinaryReader(provider, false);

			ArrayList<DataTypeComponent> list = new ArrayList<>();

			// assume APS2 format
			list.add(new ReadOnlyDataTypeComponent(StringDataType.dataType, this, 4, 0, 0, "format",
				null));
			reader.setPointerIndex(4);

			LEB128Info sleb128 = LEB128Info.parse(reader, true);
			long remainingRelocations = sleb128.value;
			list.add(sleb128.getComponent(this, list.size(), "reloc_count", null));

			sleb128 = LEB128Info.parse(reader, true);
			long baseRelocOffset = sleb128.value;
			list.add(sleb128.getComponent(this, list.size(), "reloc_baseOffset", null));

			int groupIndex = 0;
			long groupRelocOffset = baseRelocOffset;
			while (remainingRelocations > 0) {
				// NOTE: assumes 2-GByte MemBuffer limit
				int offset = (int) reader.getPointerIndex();

				long groupSize = LEB128.readAsLong(reader, true);
				if (groupSize > remainingRelocations) {
					Msg.debug(this, "Group relocation count " + groupSize +
						" exceeded total count " + remainingRelocations);
					break;
				}

				AndroidElfRelocationGroup group =
					new AndroidElfRelocationGroup(dataMgr, groupRelocOffset);
				WrappedMemBuffer groupBuffer = new WrappedMemBuffer(buf, offset);
				int groupLength = group.getLength(groupBuffer, -1);
				DataTypeComponent dtc = new ReadOnlyDataTypeComponent(group, this, groupLength,
					list.size(), offset, "reloc_group_" + groupIndex++, null);
				list.add(dtc);

				groupRelocOffset = group.getLastRelocationOffset(groupBuffer);
				if (groupRelocOffset < 0) {
					break;
				}

				offset += groupLength;
				reader.setPointerIndex(offset);

				remainingRelocations -= groupSize;
			}

			DataTypeComponent[] comps = new DataTypeComponent[list.size()];
			return list.toArray(comps);
		}
		catch (IOException e) {
			return null;
		}
	}

}
