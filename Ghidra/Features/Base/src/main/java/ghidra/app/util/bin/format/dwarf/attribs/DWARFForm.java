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
package ghidra.app.util.bin.format.dwarf.attribs;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeClass.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.LEB128Info;
import ghidra.program.model.data.LEB128;

/**
 * DWARF attribute encodings.
 * <p>
 * Unknown encodings will prevent deserialization of DIE records.
 */
public enum DWARFForm {

	DW_FORM_addr(0x1, DWARFForm.DYNAMIC_SIZE, address) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			return context.compUnit().getPointerSize();
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFNumericAttribute(
				context.reader().readNextUnsignedValue(context.compUnit().getPointerSize()),
				context.def());
		}
	},
	DW_FORM_block2(0x3, DWARFForm.DYNAMIC_SIZE, block) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			int arraySize = context.reader().readNextUnsignedShort();
			return 2 /*sizeof short */ + arraySize;
		}
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedShort();
			return new DWARFBlobAttribute(context.reader().readNextByteArray(length),
				context.def());
		}
	},
	DW_FORM_block4(0x4, DWARFForm.DYNAMIC_SIZE, block) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			int arraySize = context.reader().readNextUnsignedIntExact();
			return 4 /*sizeof int */ + arraySize;
		}
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedIntExact();
			if (length < 0 || length > MAX_BLOCK4_SIZE) {
				throw new IOException("Invalid/bad dw_form_block4 size: " + length);
			}
			return new DWARFBlobAttribute(context.reader().readNextByteArray(length),
				context.def());
		}
	},
	DW_FORM_data2(0x5, 2, constant),
	DW_FORM_data4(0x6, 4, constant),
	DW_FORM_data8(0x7, 8, constant),
	DW_FORM_string(0x8, DWARFForm.DYNAMIC_SIZE, string) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			long start = context.reader().getPointerIndex();
			context.reader().readNextUtf8String();
			return context.reader().getPointerIndex() - start;
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFStringAttribute(context.reader().readNextUtf8String(), context.def());
		}
	},
	DW_FORM_block(0x9, DWARFForm.DYNAMIC_SIZE, block) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			LEB128Info uleb128 = context.reader().readNext(LEB128Info::unsigned);
			return uleb128.getLength() + uleb128.asUInt32();
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			if (length < 0 || length > MAX_BLOCK4_SIZE) {
				throw new IOException("Invalid/bad dw_form_block size: " + length);
			}
			return new DWARFBlobAttribute(context.reader().readNextByteArray(length),
				context.def());
		}
	},
	DW_FORM_block1(0xa, DWARFForm.DYNAMIC_SIZE, block) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedByte();
			return 1 /* sizeof byte */ + length;
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedByte();
			return new DWARFBlobAttribute(context.reader().readNextByteArray(length),
				context.def());
		}
	},
	DW_FORM_data1(0xb, 1, constant),
	DW_FORM_flag(0xc, 1, flag) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFBooleanAttribute(context.reader().readNextByte() != 0, context.def());
		}
	},
	DW_FORM_sdata(0xd, DWARFForm.LEB128_SIZE, constant) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFNumericAttribute(64, context.reader().readNext(LEB128::signed), true,
				context.def());
		}
	},
	DW_FORM_strp(0xe, DWARFForm.DWARF_INTSIZE, string) {
		// offset in .debug_str
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			long stringOffset = context.reader().readNextUnsignedValue(context.dwarfIntSize());
			return new DWARFDeferredStringAttribute(stringOffset, context.def());
		}
	},
	DW_FORM_udata(0xf, DWARFForm.LEB128_SIZE, constant) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFNumericAttribute(64, context.reader().readNext(LEB128::unsigned), false,
				context.def());
		}
	},
	DW_FORM_ref_addr(0x10, DWARFForm.DWARF_INTSIZE, reference) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			long addr = context.reader().readNextUnsignedValue(context.dwarfIntSize());
			return new DWARFNumericAttribute(addr, context.def());
		}
	},
	DW_FORM_ref1(0x11, 1, reference),
	DW_FORM_ref2(0x12, 2, reference),
	DW_FORM_ref4(0x13, 4, reference),
	DW_FORM_ref8(0x14, 8, reference),
	DW_FORM_ref_udata(0x15, DWARFForm.LEB128_SIZE, constant) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			long uoffset = context.reader().readNext(LEB128::unsigned);
			return new DWARFNumericAttribute(uoffset + context.compUnit().getStartOffset(),
				context.def());
		}
	},
	DW_FORM_indirect(0x16, DWARFForm.DYNAMIC_SIZE /* value class will depend on the indirect form*/ ) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			long start = context.reader().getPointerIndex();
			int indirectFormInt = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			long firstSize = context.reader().getPointerIndex() - start;

			DWARFForm indirectForm = DWARFForm.of(indirectFormInt);
			DWARFAttributeDef<?> indirectAS = context.def().withForm(indirectForm);
			DWARFFormContext indirectContext =
				new DWARFFormContext(context.reader(), context.compUnit(), indirectAS);
			long indirectSize = indirectForm.getSize(indirectContext);

			return firstSize + indirectSize;
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int indirectFormInt = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			DWARFForm indirectForm = DWARFForm.of(indirectFormInt);
			DWARFAttributeDef<?> indirectAS = context.def().withForm(indirectForm);
			DWARFFormContext indirectContext =
				new DWARFFormContext(context.reader(), context.compUnit(), indirectAS);
			return indirectForm.readValue(indirectContext);
		}
	},
	DW_FORM_sec_offset(0x17, DWARFForm.DWARF_INTSIZE, addrptr, lineptr, loclist, loclistsptr, macptr, rnglist, rnglistsptr, stroffsetsptr) {
		// offset in a section other than .debug_info or .debug_str
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			long addr = context.reader().readNextUnsignedValue(context.dwarfIntSize());
			return new DWARFNumericAttribute(addr, context.def());
		}
	},
	DW_FORM_exprloc(0x18, DWARFForm.DYNAMIC_SIZE, exprloc) {
		@Override
		public long getSize(DWARFFormContext context) throws IOException {
			LEB128Info uleb128 = context.reader().readNext(LEB128Info::unsigned);
			return uleb128.getLength() + uleb128.asInt32();
		}

		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int length = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			if (length < 0 || length > MAX_BLOCK4_SIZE) {
				throw new IOException("Invalid/bad dw_form_exprloc size: " + length);
			}
			return new DWARFBlobAttribute(context.reader().readNextByteArray(length),
				context.def());

		}
	},
	DW_FORM_flag_present(0x19, 0, flag) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFBooleanAttribute(true, context.def());
		}
	},
	DW_FORM_strx(0x1a, DWARFForm.LEB128_SIZE, string) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int index = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			return new DWARFDeferredStringAttribute(index, context.def());
		}
	},
	DW_FORM_addrx(0x1b, DWARFForm.LEB128_SIZE, address) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			int index = context.reader().readNextUnsignedVarIntExact(LEB128::unsigned);
			return new DWARFIndirectAttribute(index, context.def());
		}
	},
	DW_FORM_ref_sup4(0x1c, 4, reference), // unimpl
	DW_FORM_strp_sup(0x1d, DWARFForm.DWARF_INTSIZE, string), // unimpl
	DW_FORM_data16(0x1e, 16, constant) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFBlobAttribute(context.reader().readNextByteArray(16), context.def());
		}
	},
	DW_FORM_line_strp(0x1f, DWARFForm.DWARF_INTSIZE, string) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFDeferredStringAttribute(
				context.reader().readNextUnsignedValue(context.dwarfIntSize()), context.def());
		}
	},
	DW_FORM_ref_sig8(0x20, 8, reference), // unimpl
	DW_FORM_implicit_const(0x21, 0) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFNumericAttribute(64, context.def().getImplicitValue(), true,
				context.def());
		}
	},
	DW_FORM_loclistx(0x22, DWARFForm.LEB128_SIZE, loclist) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFIndirectAttribute(context.reader().readNext(LEB128::unsigned),
				context.def());
		}
	},
	DW_FORM_rnglistx(0x23, DWARFForm.LEB128_SIZE, rnglist) {
		@Override
		public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
			return new DWARFIndirectAttribute(context.reader().readNext(LEB128::unsigned),
				context.def());
		}
	},
	DW_FORM_ref_sup8(0x24, 8, reference), // unimpl
	DW_FORM_strx1(0x25, 1, string),
	DW_FORM_strx2(0x26, 2, string),
	DW_FORM_strx3(0x27, 3, string),
	DW_FORM_strx4(0x28, 4, string),
	DW_FORM_addrx1(0x29, 1, address),
	DW_FORM_addrx2(0x2a, 2, address),
	DW_FORM_addrx3(0x2b, 3, address),
	DW_FORM_addrx4(0x2c, 4, address);

	private final int id;
	/**
	 * The static size of values of this type, or one of the special values {@link #DYNAMIC_SIZE},
	 * {@link #DWARF_INTSIZE}, {@link #LEB128_SIZE}
	 */
	private final int size;
	private final Set<DWARFAttributeClass> attributeClasses;

	private static final Map<Integer, DWARFForm> lookupMap = buildLookupmap();

	DWARFForm(int id, int size, DWARFAttributeClass... attributeClasses) {
		this.id = id;
		this.size = size;
		this.attributeClasses = EnumSet.noneOf(DWARFAttributeClass.class);
		this.attributeClasses.addAll(List.of(attributeClasses));
	}

	/**
	 * Returns the id of this DWARFForm.
	 * 
	 * @return DWARFForm numeric id
	 */
	public int getId() {
		return this.id;
	}

	public Set<DWARFAttributeClass> getFormClasses() {
		return attributeClasses;
	}

	public boolean isClass(DWARFAttributeClass attrClass) {
		return attributeClasses.size() == 1 && attributeClasses.contains(attrClass);
	}

	/**
	 * Returns the size the attribute value occupies in the stream.
	 * <p>
	 * This default implementation handles static sizes, as well as LEB128 and DWARF_INT sizes.
	 * DWARFForms that are more complex and marked as {@link #DYNAMIC_SIZE} will need to override
	 * this method and provide custom logic to determine the size of a value.
	 * 
	 * @param context {@link DWARFFormContext}
	 * @return size of the attribute value
	 * @throws IOException if error reading
	 */
	public long getSize(DWARFFormContext context) throws IOException {
		switch (size) {
			case DWARF_INTSIZE:
				return context.compUnit().getIntSize();
			case LEB128_SIZE:
				return context.reader().readNext(LEB128::getLength);
			case DYNAMIC_SIZE:
				throw new IOException("Unimplemented size for " + this);
			default:
				return size;
		}
	}

	/**
	 * Reads a DIE attribute value from a stream.
	 * 
	 * @param context {@link DWARFFormContext}
	 * @return {@link DWARFAttributeValue}
	 * @throws IOException if error reading
	 */
	public DWARFAttributeValue readValue(DWARFFormContext context) throws IOException {
		switch (this) {
			case DW_FORM_addrx1:
			case DW_FORM_addrx2:
			case DW_FORM_addrx3:
			case DW_FORM_addrx4: {
				long index = context.reader().readNextUnsignedValue(size);
				return new DWARFIndirectAttribute(index, context.def());
			}

			case DW_FORM_data1:
			case DW_FORM_data2:
			case DW_FORM_data4:
			case DW_FORM_data8: {
				long val = context.reader().readNextValue(size);
				return new DWARFNumericAttribute(size * 8, val, true, true, context.def());
			}
				
			case DW_FORM_ref1:
			case DW_FORM_ref2:
			case DW_FORM_ref4:
			case DW_FORM_ref8: {
				long uoffset = context.reader().readNextUnsignedValue(size);
				return new DWARFNumericAttribute(uoffset + context.compUnit().getStartOffset(),
					context.def());
			}

			case DW_FORM_strx1:
			case DW_FORM_strx2:
			case DW_FORM_strx3:
			case DW_FORM_strx4: {
				long index = context.reader().readNextUnsignedValue(size);
				return new DWARFDeferredStringAttribute(index, context.def());
			}

			default:
				throw new IllegalArgumentException("Unsupported DWARF Form: " + this);
		}
	}

	public static final int EOL = 0; // value used as end of attributespec list

	/**
	 * Find the form value given raw int.
	 * 
	 * @param key value to check
	 * @return DWARFForm enum, or null if it is an unknown form
	 */
	public static DWARFForm of(int key) {
		return lookupMap.get(key);
	}

	private static Map<Integer, DWARFForm> buildLookupmap() {
		Map<Integer, DWARFForm> result = new HashMap<>();
		for (DWARFForm form : DWARFForm.values()) {
			result.put(form.getId(), form);
		}
		return result;

	}

	public static final int MAX_BLOCK4_SIZE = 1024 * 1024;
	private static final int LEB128_SIZE = -3;
	private static final int DWARF_INTSIZE = -2;
	private static final int DYNAMIC_SIZE = -1;
}
