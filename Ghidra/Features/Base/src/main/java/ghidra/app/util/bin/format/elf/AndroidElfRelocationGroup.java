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

import javax.help.UnsupportedOperationException;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.AndroidElfRelocationTableDataType.LEB128Info;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.WrappedMemBuffer;
import ghidra.program.model.scalar.Scalar;

/**
 * <code>AndroidElfRelocationGroup</code> provides a dynamic substructure 
 * component for relocation groups within a packed Android ELF Relocation Table.
 * See {@link AndroidElfRelocationTableDataType}.
 */
class AndroidElfRelocationGroup extends DynamicDataType {

	// Packed Android APS2 relocation group flags
	static final long RELOCATION_GROUPED_BY_INFO_FLAG = 1;
	static final long RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
	static final long RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
	static final long RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

	private final long baseRelocOffset;

	AndroidElfRelocationGroup(DataTypeManager dtm, long baseRelocOffset) {
		super(CategoryPath.ROOT, "AndroidElfRelocationGroup", dtm);
		this.baseRelocOffset = baseRelocOffset;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		// specific instances are used by AndroidElfRelocationTableDatatype
		throw new UnsupportedOperationException("may not be cloned");
	}

	@Override
	public String getDescription() {
		return "Android Packed Relocation Entry Group for ELF";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {

		try {
			ByteProvider provider = new MemBufferByteProvider(buf);
			BinaryReader reader = new BinaryReader(provider, false);

			ArrayList<DataTypeComponent> list = new ArrayList<>();

			LEB128Info sleb128 = LEB128Info.parse(reader, true);
			long groupSize = sleb128.value;
			list.add(sleb128.getComponent(this, list.size(), "group_size", null));

			sleb128 = LEB128Info.parse(reader, true);
			long groupFlags = sleb128.value;
			list.add(sleb128.getComponent(this, list.size(), "group_flags", null));

			boolean groupedByInfo = (groupFlags & RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
			boolean groupedByDelta = (groupFlags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
			boolean groupedByAddend = (groupFlags & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
			boolean groupHasAddend = (groupFlags & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;

			long groupOffsetDelta = 0;
			if (groupedByDelta) {
				sleb128 = LEB128Info.parse(reader, true);
				groupOffsetDelta = sleb128.value;

				long minOffset = baseRelocOffset + groupOffsetDelta;
				String rangeStr = "First relocation offset: 0x" + Long.toHexString(minOffset);

				list.add(sleb128.getComponent(this, list.size(), "group_offsetDelta", rangeStr));
			}

			if (groupedByInfo) {
				sleb128 = LEB128Info.parse(reader, true);
				list.add(sleb128.getComponent(this, list.size(), "group_info", null));
			}

			if (groupedByAddend && groupHasAddend) {
				sleb128 = LEB128Info.parse(reader, true);
				list.add(sleb128.getComponent(this, list.size(), "group_addend", null));
			}

			long relocOffset = baseRelocOffset;

			if (groupedByDelta && groupedByInfo && (!groupHasAddend || groupedByAddend)) {
				// no individual relocation entry data
				relocOffset += (groupSize - 1) * groupOffsetDelta;
			}
			else {
				for (int i = 0; i < groupSize; i++) {
					if (groupedByDelta) {
						relocOffset += groupOffsetDelta;
					}
					else {
						sleb128 = LEB128Info.parse(reader, true);
						long baseOffset = relocOffset;
						relocOffset += sleb128.value;
						DataTypeComponent dtc = new ReadOnlyDataTypeComponent(
							new AndroidElfRelocationOffset(dataMgr, baseOffset, relocOffset), this,
							sleb128.byteLength, list.size(), sleb128.offset, "reloc_offset_" + i,
							null);
						list.add(dtc);
					}

					if (!groupedByInfo) {
						sleb128 = LEB128Info.parse(reader, true);
						list.add(sleb128.getComponent(this, list.size(), "reloc_info_" + i, null,
							relocOffset));
					}

					if (groupHasAddend && !groupedByAddend) {
						sleb128 = LEB128Info.parse(reader, true);
						list.add(sleb128.getComponent(this, list.size(), "reloc_addend_" + i, null,
							relocOffset));
					}
				}
			}

			DataTypeComponent[] comps = new DataTypeComponent[list.size()];
			return list.toArray(comps);
		}
		catch (IOException e) {
			return null;
		}
	}

	long getLastRelocationOffset(WrappedMemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if ((comps == null) || (comps.length < 3)) {
			return -1;
		}

		// group_size component
		Scalar s = (Scalar) comps[0].getDataType().getValue(buf, null, comps[0].getLength());
		int groupSize = (int) s.getValue();

		DataTypeComponent lastDtc = comps[comps.length - 1];

		if ("group_offsetDelta".equals(comps[2].getFieldName())) {
			WrappedMemBuffer cbuf = new WrappedMemBuffer(buf, comps[2].getOffset());
			s = (Scalar) comps[2].getDataType().getValue(cbuf, null, comps[2].getLength());
			long groupOffsetDelta = s.getValue();
			return baseRelocOffset + ((groupSize - 1) * groupOffsetDelta);
		}

		if (lastDtc.getFieldName().startsWith("group_")) {
			return -1; // unexpected
		}

		DataType dt = lastDtc.getDataType();
		if (dt instanceof AndroidElfRelocationOffset) {
			AndroidElfRelocationOffset d = (AndroidElfRelocationOffset) dt;
			return d.getRelocationOffset(); // return stashed offset
		}
		else if (dt instanceof AndroidElfRelocationData) {
			AndroidElfRelocationData d = (AndroidElfRelocationData) dt;
			return d.getRelocationOffset(); // return stashed offset
		}
		return -1; // unexpected
	}
}
