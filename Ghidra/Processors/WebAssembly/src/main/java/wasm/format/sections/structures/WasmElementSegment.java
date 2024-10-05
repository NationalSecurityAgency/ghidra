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
package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.WasmLoader;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;

public class WasmElementSegment implements StructConverter {

	private LEB128Info flags;
	private ElementSegmentMode mode;

	private LEB128Info tableidx; /* if (flags & 3) == 2 */
	private ConstantExpression offset; /* if (flags & 1) == 0 */
	private LEB128Info count;

	int elemkind; /* if (flags & 4) == 0 */
	private List<LEB128Info> funcidxs; /* if (flags & 4) == 0 */

	ValType elemtype; /* if (flags & 4) != 0 */
	private List<ConstantExpression> exprs; /* if (flags & 4) != 0 */

	public enum ElementSegmentMode {
		active,
		passive,
		declarative,
	}

	public WasmElementSegment(BinaryReader reader) throws IOException {
		flags = reader.readNext(LEB128Info::unsigned);
		long flagVal = flags.asLong();
		if ((flagVal & 3) == 2) {
			/* active segment with explicit table index */
			tableidx = reader.readNext(LEB128Info::unsigned);
		} else {
			/* tableidx defaults to 0 */
			tableidx = null;
		}

		if ((flagVal & 1) == 0) {
			/* active segment */
			mode = ElementSegmentMode.active;
			offset = new ConstantExpression(reader);
		} else if ((flagVal & 2) == 0) {
			mode = ElementSegmentMode.passive;
		} else {
			mode = ElementSegmentMode.declarative;
		}

		if ((flagVal & 3) == 0) {
			/* implicit element type */
			elemkind = 0;
			elemtype = ValType.funcref;
		} else {
			/* explicit element type */
			int typeCode = reader.readNextUnsignedByte();
			if ((flagVal & 4) == 0) {
				/* elemkind */
				elemkind = typeCode;
			} else {
				/* reftype */
				elemtype = ValType.fromByte(typeCode);
			}
		}

		count = reader.readNext(LEB128Info::unsigned);
		if ((flagVal & 4) == 0) {
			/* vector of funcidx */
			funcidxs = new ArrayList<>();
			for (int i = 0; i < count.asLong(); i++) {
				funcidxs.add(reader.readNext(LEB128Info::unsigned));
			}
		} else {
			/* vector of expr */
			exprs = new ArrayList<>();
			for (int i = 0; i < count.asLong(); i++) {
				exprs.add(new ConstantExpression(reader));
			}
		}
	}

	public ElementSegmentMode getMode() {
		return mode;
	}

	public long getTableIndex() {
		if (tableidx == null) {
			return 0;
		}
		return tableidx.asLong();
	}

	public Long getOffset() {
		if (offset == null) {
			return null;
		}
		return offset.asI32();
	}

	public ValType getElementType() {
		if ((flags.asLong() & 4) == 0) {
			if (elemkind == 0) {
				return ValType.funcref;
			}
			return null;
		} else {
			return elemtype;
		}
	}

	public Address[] getAddresses(AddressFactory addressFactory, WasmModule module) {
		int count = (int) this.count.asLong();
		Address[] result = new Address[count];

		if (funcidxs != null) {
			for (int i = 0; i < count; i++) {
				long funcidx = funcidxs.get(i).asLong();
				result[i] = WasmLoader.getFunctionAddress(addressFactory, module, (int) funcidx);
			}
			return result;
		}

		if (exprs != null) {
			for (int i = 0; i < count; i++) {
				result[i] = exprs.get(i).asAddress(addressFactory, module);
			}
			return result;
		}
		return null;
	}

	public byte[] getInitData(WasmModule module) {
		int elemSize = getElementType().getSize();
		int count = (int) this.count.asLong();
		byte[] result = new byte[count * elemSize];
		Arrays.fill(result, (byte) 0x00);

		if (funcidxs != null) {
			for (int i = 0; i < count; i++) {
				long funcidx = funcidxs.get(i).asLong();
				long funcaddr = WasmLoader.getFunctionAddressOffset(module, (int) funcidx);
				byte[] v = ConstantExpression.longToBytes(funcaddr);
				System.arraycopy(v, 0, result, i * elemSize, elemSize);
			}
			return result;
		}

		if (exprs != null) {
			for (int i = 0; i < count; i++) {
				byte[] v = exprs.get(i).asBytes(module);
				if (v != null)
					System.arraycopy(v, 0, result, i * elemSize, elemSize);
			}
			return result;
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("element_segment");
		builder.addUnsignedLeb128(flags, "flags");
		if (tableidx != null) {
			builder.addUnsignedLeb128(tableidx, "tableidx");
		}
		if (offset != null) {
			builder.add(offset, "offset");
		}
		if ((flags.asLong() & 3) != 0) {
			/* both elemkind and reftype are single bytes */
			builder.add(BYTE, "element_type");
		}

		builder.addUnsignedLeb128(count, "count");
		if (funcidxs != null) {
			for (int i = 0; i < funcidxs.size(); i++) {
				builder.addUnsignedLeb128(funcidxs.get(i), "element" + i);
			}
		}
		if (exprs != null) {
			for (int i = 0; i < exprs.size(); i++) {
				builder.add(exprs.get(i), "element" + i);
			}
		}

		return builder.toStructure();
	}
}
