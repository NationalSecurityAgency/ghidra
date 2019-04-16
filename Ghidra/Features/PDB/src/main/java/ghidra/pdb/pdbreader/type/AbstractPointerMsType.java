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

import java.util.HashMap;
import java.util.Map;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Pointer type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractPointerMsType extends AbstractMsType {

	public enum PointerType {

		INVALID("invalid", -1),
		NEAR("near", 0), // 16-bit pointer
		FAR("far", 1), // 16:16  far pointer
		HUGE("huge", 2), // 16:16 huge pointer
		SEGMENT_BASED("base(seg)", 3),
		VALUE_BASED("base(val)", 4),
		SEGMENT_VALUE_BASED("base(segval)", 5),
		ADDRESS_BASED("base(addr)", 6),
		SEGMENT_ADDRESS_BASED("base(segaddr)", 7),
		TYPE_BASED("base(type)", 8),
		SELF_BASED("base(addr)", 9),
		NEAR32("", 10), // 32-bit pointer
		FAR32("far32", 11), // 16:32 pointer
		PTR64("far64", 12), // 64-bit pointer
		UNSPECIFIED("unspecified", 13);

		private static final Map<Integer, PointerType> BY_VALUE = new HashMap<>();
		static {
			for (PointerType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static PointerType fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private PointerType(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	public enum PointerMode {

		INVALID("", -1), // Our default
		POINTER("*", 0), // Normal
		LVALUE_REFERENCE("&", 1), // Same as older style reference
		MEMBER_DATA_POINTER("::*", 2),
		MEMBER_FUNCTION_POINTER("::*", 3),
		RVALUE_REFERENCE("&&", 4),
		RESERVED("", 5);

		private static final Map<Integer, PointerMode> BY_VALUE = new HashMap<>();
		static {
			for (PointerMode val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		/**
		 * Emits {@link String} output of this class into the provided {@link StringBuilder}.
		 * @param builder The {@link StringBuilder} into which the output is created.
		 */
		public void emit(StringBuilder builder) {
			builder.append(this.getClass().getSimpleName());
		}

		@Override
		public String toString() {
			return label;
		}

		public static PointerMode fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private PointerMode(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	public enum MemberPointerType {

		INVALID("invalid", -1),
		UNSPECIFIED("pdm16_nonvirt", 0), // 16-bit pointer
		DATA_SINGLE_INHERITANCE("pdm16_vfcn", 1), // 16:16  far pointer
		DATA_MULTIPLE_INHERITANCE("pdm16_vbase", 2), // 16:16 huge pointer
		DATA_VIRTUAL_INHERITANCE("pdm32_nvvfcn", 3),
		DATA_GENERAL("pdm32_vbase", 4),
		FUNCTION_SINGLE_INHERITANCE("pmf16_nearnvsa", 5),
		FUNCTION_MULTIPLE_INHERITANCE("pmf16_nearnvma", 6),
		FUNCTION_VIRTUAL_INHERITANCE("pmf16_nearvbase", 7),
		FUNCTION_SINGLE_INHERITANCE_1632("pmf16_farnvsa", 8),
		FUNCTION_MULTIPLE_INHERITANCE_1632("pmf16_farnvma", 9),
		FUNCTION_VIRTUAL_INHERITANCE_1632("pmf16_farnvbase", 10),
		FUNCTION_SINGLE_INHERITANCE_32("pmf32_nvsa", 11),
		FUNCTION_MULTIPLE_INHERITANCE_32("pmf32_nvma", 12),
		FUNCTION_VIRTUAL_INHERITANCE_32("pmf32_nvbase", 13);

		private static final Map<Integer, MemberPointerType> BY_VALUE = new HashMap<>();
		static {
			for (MemberPointerType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static MemberPointerType fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private MemberPointerType(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	//==============================================================================================
	protected AbstractTypeIndex underlyingTypeIndex;
	protected PointerType pointerType;
	protected PointerMode pointerMode;
	protected boolean isFlat; // 0:32 pointer
	protected boolean isVolatile;
	protected boolean isConst;
	protected boolean isUnaligned;

	protected AbstractTypeIndex memberPointerContainingClassIndex;
	protected MemberPointerType memberPointerType;

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

		if (pointerMode == PointerMode.MEMBER_DATA_POINTER ||
			pointerMode == PointerMode.MEMBER_FUNCTION_POINTER) {
			memberPointerContainingClassIndex.parse(reader);
			pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA,
				memberPointerContainingClassIndex.get()));
			pdb.popDependencyStack();
			memberPointerType = MemberPointerType.fromValue(reader.parseUnsignedShortVal());
			if (reader.hasMore()) {
				//TODO: I think there might be possible padding
				reader.parseBytesRemaining();
			}
		}
		else if (pointerType == PointerType.SEGMENT_BASED) {
			baseSegment = reader.parseUnsignedShortVal();
			if (reader.hasMore()) {
				//TODO: I think there might be possible padding
				//System.out.println(reader.dump());
				reader.parseBytesRemaining();
			}
		}
		else if (pointerType == PointerType.TYPE_BASED) {
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
		else if (pointerType == PointerType.INVALID) {
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
	 * Returns {@link PointerType} attribute.
	 * @return {@link PointerType} attribute.
	 */
	public PointerType getPointerType() {
		return pointerType;
	}

	/**
	 * Returns {@link PointerMode} attribute.
	 * @return {@link PointerMode} attribute.
	 */
	public PointerMode getPointerMode() {
		return pointerMode;
	}

	/**
	 * Returns {@link MemberPointerType} attribute.
	 * @return {@link MemberPointerType} attribute.
	 */
	public MemberPointerType getMemberPointerType() {
		return memberPointerType;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(isFlat ? "flat " : "");
		switch (pointerMode) {
			case MEMBER_DATA_POINTER:
			case MEMBER_FUNCTION_POINTER:
				pdb.getTypeRecord(memberPointerContainingClassIndex.get()).emit(builder, Bind.NONE);
				myBuilder.append(pointerMode);
				myBuilder.append(" <");
				myBuilder.append(memberPointerType);
				myBuilder.append(">");
				break;
			case POINTER:
			case LVALUE_REFERENCE:
			case RVALUE_REFERENCE:
			default:
				myBuilder.append(pointerType);
				myBuilder.append(pointerMode);
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
	 * <P>
	 * Implementing class must initialize {@link #underlyingTypeIndex},
	 * {@link #memberPointerContainingClassIndex}, {@link #baseSymbol}, and {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parses the pointer body.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, call
	 * {@link #parseAttributes(PdbByteReader)} and parse {@link #underlyingTypeIndex}.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parsePointerBody(PdbByteReader reader) throws PdbException;

	/**
	 * Parses the attributes of the pointer.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, parse
	 * certain attributes, which at a minimum will fill in {@link #pointerType}, 
	 * {@link #pointerMode}, {@link #isFlat}, {@link #isVolatile}, {@link #isConst},
	 * and {@link #isUnaligned}.
	 * @param reader {@link PdbByteReader} from which the attributes are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseAttributes(PdbByteReader reader) throws PdbException;

	protected abstract int getMySize();

}
