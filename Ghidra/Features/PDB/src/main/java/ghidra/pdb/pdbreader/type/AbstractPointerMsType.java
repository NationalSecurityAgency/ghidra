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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * An abstract class for a number of specific PDB data types that share certain information.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public abstract class AbstractPointerMsType extends AbstractMsType {

	private static final int TYPE_NEAR = 0x00; // 16-bit pointer
	private static final int TYPE_FAR = 0x01; // 16:16  far pointer
	private static final int TYPE_HUGE = 0x02; // 16:16 huge pointer
	private static final int TYPE_SEGMENT_BASED = 0x03;
	private static final int TYPE_VALUE_BASED = 0x04;
	private static final int TYPE_SEGMENT_VALUE_BASED = 0x05;
	private static final int TYPE_ADDRESS_BASED = 0x06;
	private static final int TYPE_SEGMENT_ADDRESS_BASED = 0x07;
	private static final int TYPE_TYPE_BASED = 0x08;
	private static final int TYPE_SELF_BASED = 0x09;
	private static final int TYPE_NEAR32 = 0x0a; // 32-bit pointer
	private static final int TYPE_FAR32 = 0x0b; // 16:32 pointer
	private static final int TYPE_PTR64 = 0x0c; // 64-bit pointer

	private static final String[] TYPE_STRING = new String[14];
	static {
		TYPE_STRING[0] = "near";
		TYPE_STRING[1] = "far";
		TYPE_STRING[2] = "huge";
		TYPE_STRING[3] = "base(seg)";
		TYPE_STRING[4] = "base(val)";
		TYPE_STRING[5] = "base(segval)";
		TYPE_STRING[6] = "base(addr)";
		TYPE_STRING[7] = "base(segaddr)";
		TYPE_STRING[8] = "base(type)";
		TYPE_STRING[9] = "base(self)";
		TYPE_STRING[10] = "";
		TYPE_STRING[11] = "far32";
		TYPE_STRING[12] = "far64";
		TYPE_STRING[13] = "unspecified";
	}

	private static final int MODE_POINTER = 0x00; // Normal
	private static final int MODE_OLD_REFERENCE = 0x01; // Same as LVALUE_REFERENCE
	private static final int MODE_LVALUE_REFERENCE = 0x01; // Same as OLD_REFERENCE
	private static final int MODE_MEMBER_DATA_POINTER = 0x02;
	private static final int MODE_MEMBER_FUNCTION_POINTER = 0x03;
	private static final int MODE_RVALUE_REFERENCE = 0x04;
	private static final int MODE_RESERVED = 0x05;

	private static final String[] MEMBER_POINTER_ATTRIBUTE_STRING = new String[14];
	static {
		MEMBER_POINTER_ATTRIBUTE_STRING[0] = "pdm16_nonvirt";
		MEMBER_POINTER_ATTRIBUTE_STRING[1] = "pdm16_vfcn";
		MEMBER_POINTER_ATTRIBUTE_STRING[2] = "pdm16_vbase";
		MEMBER_POINTER_ATTRIBUTE_STRING[3] = "pdm32_nvvfcn";
		MEMBER_POINTER_ATTRIBUTE_STRING[4] = "pdm32_vbase";
		MEMBER_POINTER_ATTRIBUTE_STRING[5] = "pmf16_nearnvsa";
		MEMBER_POINTER_ATTRIBUTE_STRING[6] = "pmf16_nearnvma";
		MEMBER_POINTER_ATTRIBUTE_STRING[7] = "pmf16_nearvbase";
		MEMBER_POINTER_ATTRIBUTE_STRING[8] = "pmf16_farnvsa";
		MEMBER_POINTER_ATTRIBUTE_STRING[9] = "pmf16_farnvma";
		MEMBER_POINTER_ATTRIBUTE_STRING[10] = "pmf16_farvbase";
		MEMBER_POINTER_ATTRIBUTE_STRING[11] = "pmf32_nvsa";
		MEMBER_POINTER_ATTRIBUTE_STRING[12] = "pmf32_nvma";
		MEMBER_POINTER_ATTRIBUTE_STRING[13] = "pmf32_vbase";
	}

	private static final int MEMBER_POINTER_UNSPECIFIED = 0x00;
	private static final int MEMBER_POINTER_DATA_SINGLE_INHERITANCE = 0x01;
	private static final int MEMBER_POINTER_DATA_MULTIPLE_INHERITANCE = 0x02;
	private static final int MEMBER_POINTER_DATA_VIRTUAL_INHERITANCE = 0x03;
	private static final int MEMBER_POINTER_DATA_GENERAL = 0x04;
	private static final int MEMBER_POINTER_FUNCTION_SINGLE_INHERITANCE = 0x05;
	private static final int MEMBER_POINTER_FUNCTION_MULTIPLE_INHERITANCE = 0x06;
	private static final int MEMBER_POINTER_FUNCTION_VIRTUAL_INHERITANCE = 0x07;
	private static final int MEMBER_POINTER_FUNCTION_GENERAL = 0x08;

	//==============================================================================================
	protected AbstractTypeIndex underlyingTypeIndex;
	protected int pointerTypeAttribute;
	protected int pointerModeAttribute;
	protected boolean isFlat; // 0:32 pointer
	protected boolean isVolatile;
	protected boolean isConst;
	protected boolean isUnaligned;

	protected AbstractTypeIndex memberPointerContainingClassIndex;
	protected int memberPointerFormat;

	protected int baseSegment;
	protected AbstractString baseSymbol;
	protected int pointerBaseTypeIndex;
	protected AbstractString name;

	//==============================================================================================
	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractPointerMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parsePointerBody(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, underlyingTypeIndex.get()));
		pdb.popDependencyStack();

		if (pointerModeAttribute == MODE_MEMBER_DATA_POINTER ||
			pointerModeAttribute == MODE_MEMBER_FUNCTION_POINTER) {
			memberPointerContainingClassIndex.parse(reader);
			pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA,
				memberPointerContainingClassIndex.get()));
			pdb.popDependencyStack();
			memberPointerFormat = reader.parseUnsignedShortVal();
			if (reader.hasMore()) {
				//TODO: I think there might be possible padding
				reader.parseBytesRemaining();
			}
		}
		else if (pointerTypeAttribute == TYPE_SEGMENT_BASED) {
			baseSegment = reader.parseUnsignedShortVal();
			if (reader.hasMore()) {
				//TODO: I think there might be possible padding
				//System.out.println(reader.dump());
				reader.parseBytesRemaining();
			}
		}
		else if (pointerTypeAttribute == TYPE_TYPE_BASED) {
			pointerBaseTypeIndex = reader.parseInt();
			name.parse(reader);
			reader.skipPadding();
			if (reader.hasMore()) {
				//TODO: I think there might be possible padding
				//System.out.println(reader.dump());
				reader.parseBytesRemaining();
			}
		}
		// Something needs to trigger this code (might be a mode or a type
		else if (pointerTypeAttribute == -1) {
			baseSymbol.parse(reader);
			//System.out.println(reader.dump());
			reader.skipPadding();
		}
		else if (reader.hasMore()) {
			// TODO: more investigation--enable code during research.
			//System.out.println(reader.dump());
			//assert (false);
		}
		reader.skipPadding();
	}

	/**
	 * Returns the type that is pointed to.
	 * @return Type that is pointed to by this pointer.
	 */
	public AbstractMsType getUnderlyingType() {
		return pdb.getTypeRecord(underlyingTypeIndex.get());
	}

	/**
	 * Returns the type index of the type that is pointed to.
	 * @return The type index of the type that is pointed to by this pointer.
	 */
	public int getUnderlyingTypeIndex() {
		return underlyingTypeIndex.get();
	}

	/**
	 * Returns the size in bytes of the pointer.
	 * @return The size in bytes.
	 */
	public int getSize() {
		return getMySize();
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isNear() {
		return (pointerTypeAttribute == TYPE_NEAR);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFar() {
		return (pointerTypeAttribute == TYPE_FAR);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isHuge() {
		return (pointerTypeAttribute == TYPE_HUGE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isSegmentBased() {
		return (pointerTypeAttribute == TYPE_SEGMENT_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isValueBased() {
		return (pointerTypeAttribute == TYPE_VALUE_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isSegmentValueBased() {
		return (pointerTypeAttribute == TYPE_SEGMENT_VALUE_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isAddressBased() {
		return (pointerTypeAttribute == TYPE_ADDRESS_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isSegmentAddressBased() {
		return (pointerTypeAttribute == TYPE_SEGMENT_ADDRESS_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isTypeBased() {
		return (pointerTypeAttribute == TYPE_TYPE_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isSelfBased() {
		return (pointerTypeAttribute == TYPE_SELF_BASED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isNear32() {
		return (pointerTypeAttribute == TYPE_NEAR32);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFar32() {
		return (pointerTypeAttribute == TYPE_FAR32);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isPtr64() {
		return (pointerTypeAttribute == TYPE_PTR64);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isNormal() {
		return (pointerModeAttribute == MODE_POINTER);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isLOldReference() {
		return (pointerModeAttribute == MODE_OLD_REFERENCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isLValueReference() {
		return (pointerModeAttribute == MODE_LVALUE_REFERENCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isMemberDataPointer() {
		return (pointerModeAttribute == MODE_MEMBER_DATA_POINTER);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isMemberFunctionPointer() {
		return (pointerModeAttribute == MODE_MEMBER_FUNCTION_POINTER);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFValueReference() {
		return (pointerModeAttribute == MODE_RVALUE_REFERENCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isModeReserved() {
		return (pointerModeAttribute == MODE_RESERVED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isUnspecified() {
		return (memberPointerFormat == MEMBER_POINTER_UNSPECIFIED);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isDataSingleInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_DATA_SINGLE_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isDataMultipleInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_DATA_MULTIPLE_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isDataVirtualInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_DATA_VIRTUAL_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isDataGeneral() {
		return (memberPointerFormat == MEMBER_POINTER_DATA_GENERAL);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFunctionSingleInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_FUNCTION_SINGLE_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFunctionMultipleInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_FUNCTION_MULTIPLE_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFunctionVirtualInheritance() {
		return (memberPointerFormat == MEMBER_POINTER_FUNCTION_VIRTUAL_INHERITANCE);
	}

	/**
	 * Returns boolean regarding the fact of the property.
	 * @return Truth about the property.
	 */
	public boolean isFunctionGeneral() {
		return (memberPointerFormat == MEMBER_POINTER_FUNCTION_GENERAL);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(isFlat ? "flat " : "");
		switch (pointerModeAttribute) {
			case MODE_POINTER:
				myBuilder.append(TYPE_STRING[pointerTypeAttribute]);
				myBuilder.append("*");
				break;
			case MODE_LVALUE_REFERENCE:
				myBuilder.append(TYPE_STRING[pointerTypeAttribute]);
				myBuilder.append("&");
				break;
			case MODE_RVALUE_REFERENCE:
				myBuilder.append(TYPE_STRING[pointerTypeAttribute]);
				myBuilder.append("&&");
				break;
			case MODE_MEMBER_DATA_POINTER:
			case MODE_MEMBER_FUNCTION_POINTER:
				pdb.getTypeRecord(memberPointerContainingClassIndex.get()).emit(builder, Bind.NONE);
				myBuilder.append("::* <");
				myBuilder.append(MEMBER_POINTER_ATTRIBUTE_STRING[memberPointerFormat]);
				myBuilder.append(">");
				break;
		}
		myBuilder.append(isConst ? "const " : "");
		myBuilder.append(isVolatile ? "volatile " : "");

		myBuilder.append(" "); //redundant space if const or volatile---TODO: fix
		builder.insert(0, myBuilder);
		builder.append(" ");
		getUnderlyingType().emit(builder, Bind.PTR);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

	/**
	 * Parses the pointer body.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parsePointerBody(PdbByteReader reader) throws PdbException;

	/**
	 * Parses the attributes of the pointer.
	 * @param reader {@link PdbByteReader} frmo which the attributes are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseAttributes(PdbByteReader reader) throws PdbException;

	protected abstract int getMySize();

}
