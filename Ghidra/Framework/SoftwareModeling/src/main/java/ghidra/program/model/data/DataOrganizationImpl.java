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

import java.util.Arrays;

import ghidra.program.model.lang.Language;
import ghidra.util.datastruct.IntIntHashtable;
import ghidra.util.exception.NoValueException;

/**
 * DataOrganization provides a single place for determining size and alignment information 
 * for data types within an archive or a program.
 */
public class DataOrganizationImpl implements DataOrganization {

	private int absoluteMaxAlignment = NO_MAXIMUM_ALIGNMENT;
	private int machineAlignment = 8;
	private int defaultAlignment = 1;
	private int defaultPointerAlignment = 4;

	// Default sizes for primitive data types.
	private int pointerShift = 0;
	private int pointerSize = 4;
	private int charSize = 1;
	private int wideCharSize = 2;
	private int shortSize = 2;
	private int integerSize = 4;
	private int longSize = 4;
	private int longLongSize = 8;
	private int floatSize = 4;
	private int doubleSize = 8;
	private int longDoubleSize = 8;

	private boolean bigEndian = false;
	private boolean isSignedChar = true;

	private BitFieldPacking bitFieldPacking = new BitFieldPackingImpl();

	/*
	 * Map for determining the alignment of a data type based upon its size.
	 */
	private final IntIntHashtable sizeAlignmentMap = new IntIntHashtable();

	/**
	 * Creates a new default DataOrganization. This has a mapping which defines the alignment
	 * of a data type based on its size. The map defines pairs for data types that are
	 * 1, 2, 4, and 8 bytes in length.
	 * @return a new default DataOrganization.
	 */
	public static DataOrganization getDefaultOrganization() {
		return getDefaultOrganization(null);
	}

	/**
	 * Creates a new default DataOrganization. This has a mapping which defines the alignment
	 * of a data type based on its size. The map defines pairs for data types that are
	 * 1, 2, 4, and 8 bytes in length.
	 * @param language optional language used to initialize defaults (pointer size, endianess, etc.) (may be null)
	 * @return a new default DataOrganization.
	 */
	public static DataOrganizationImpl getDefaultOrganization(Language language) {
		DataOrganizationImpl dataOrganization = new DataOrganizationImpl();
		dataOrganization.setSizeAlignment(1, 1);
		dataOrganization.setSizeAlignment(2, 2);
		dataOrganization.setSizeAlignment(4, 4);
		dataOrganization.setSizeAlignment(8, 4);
		if (language != null) {
			dataOrganization.setPointerSize(language.getDefaultSpace().getPointerSize());
			dataOrganization.setBigEndian(language.isBigEndian());
		}
		return dataOrganization;
	}

	/**
	 * Creates a new default DataOrganization with an empty size to alignment mapping.
	 */
	private DataOrganizationImpl() {
	}

	@Override
	public boolean isBigEndian() {
		return bigEndian;
	}

	@Override
	public int getPointerSize() {
		return pointerSize;
	}

	@Override
	public int getPointerShift() {
		return pointerShift;
	}

	@Override
	public boolean isSignedChar() {
		return isSignedChar;
	}

	@Override
	public int getCharSize() {
		return charSize;
	}

	@Override
	public int getWideCharSize() {
		return wideCharSize;
	}

	@Override
	public int getShortSize() {
		return shortSize;
	}

	@Override
	public int getIntegerSize() {
		return integerSize;
	}

	@Override
	public int getLongSize() {
		return longSize;
	}

	@Override
	public int getLongLongSize() {
		return longLongSize;
	}

	@Override
	public int getFloatSize() {
		return floatSize;
	}

	@Override
	public int getDoubleSize() {
		return doubleSize;
	}

	@Override
	public int getLongDoubleSize() {
		return longDoubleSize;
	}

	@Override
	public BitFieldPacking getBitFieldPacking() {
		return bitFieldPacking;
	}

	/**
	 * Set data endianess
	 * @param bigEndian
	 */
	public void setBigEndian(boolean bigEndian) {
		this.bigEndian = bigEndian;
	}

	/**
	 * Defines the size of a pointer data type.
	 * @param pointerSize the size of a pointer.
	 */
	public void setPointerSize(int pointerSize) {
		this.pointerSize = pointerSize;
	}

	/**
	 * Defines the left shift amount for a shifted pointer data type.
	 * Shift amount affects interpretation of in-memory pointer values only
	 * and will also be reflected within instruction pcode.
	 * @param pointerShift left shift amount for in-memory pointer values
	 */
	public void setPointerShift(int pointerShift) {
		this.pointerShift = pointerShift;
	}

	/**
	 * Defines the signed-ness of the "char" data type
	 * @param signed true if "char" type is signed
	 */
	public void setCharIsSigned(boolean signed) {
		this.isSignedChar = signed;
	}

	/**
	 * Defines the size of a char (char) data type.
	 * @param charSize the size of a char (char).
	 */
	public void setCharSize(int charSize) {
		this.charSize = charSize;
	}

	/**
	 * Defines the size of a wide-char (wchar_t) data type.
	 * @param wideCharSize the size of a wide-char (wchar_t).
	 */
	public void setWideCharSize(int wideCharSize) {
		this.wideCharSize = wideCharSize;
	}

	/**
	 * Defines the size of a short primitive data type.
	 * @param shortSize the size of a short.
	 */
	public void setShortSize(int shortSize) {
		this.shortSize = shortSize;
		if (integerSize < shortSize) {
			setIntegerSize(shortSize);
		}
	}

	/**
	 * Defines the size of an int primitive data type.
	 * @param integerSize the size of an int.
	 */
	public void setIntegerSize(int integerSize) {
		this.integerSize = integerSize;
		if (longSize < integerSize) {
			setLongSize(integerSize);
		}
		if (shortSize > integerSize) {
			setShortSize(integerSize);
		}
	}

	/**
	 * Defines the size of a long primitive data type.
	 * @param longSize the size of a long.
	 */
	public void setLongSize(int longSize) {
		this.longSize = longSize;
		if (longLongSize < longSize) {
			setLongLongSize(longSize);
		}
		if (integerSize > longSize) {
			setIntegerSize(longSize);
		}
	}

	/**
	 * Defines the size of a long long primitive data type.
	 * @param longLongSize the size of a long long.
	 */
	public void setLongLongSize(int longLongSize) {
		this.longLongSize = longLongSize;
		if (longSize > longLongSize) {
			setLongSize(longLongSize);
		}
	}

	/**
	 * Defines the size of a float primitive data type.
	 * @param floatSize the size of a float.
	 */
	public void setFloatSize(int floatSize) {
		this.floatSize = floatSize;
		if (doubleSize < floatSize) {
			setDoubleSize(floatSize);
		}
	}

	/**
	 * Defines the size of a double primitive data type.
	 * @param doubleSize the size of a double.
	 */
	public void setDoubleSize(int doubleSize) {
		this.doubleSize = doubleSize;
		if (longDoubleSize < doubleSize) {
			setLongDoubleSize(doubleSize);
		}
		if (floatSize > doubleSize) {
			setFloatSize(doubleSize);
		}
	}

	/**
	 * Defines the size of a long double primitive data type.
	 * @param longDoubleSize the size of a long double.
	 */
	public void setLongDoubleSize(int longDoubleSize) {
		this.longDoubleSize = longDoubleSize;
		if (doubleSize > longDoubleSize) {
			setDoubleSize(longDoubleSize);
		}
	}

	// DEFAULT ALIGNMENTS

	/**
	 * Gets the maximum alignment value that is allowed by this data organization. When getting
	 * an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
	 * is returned, the data organization isn't specifically limited.
	 * @return the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
	 */
	@Override
	public int getAbsoluteMaxAlignment() {
		return absoluteMaxAlignment;
	}

	/**
	 * Gets the maximum useful alignment for the target machine
	 * @return the machine alignment
	 */
	@Override
	public int getMachineAlignment() {
		return machineAlignment;
	}

	/**
	 * Gets the default alignment to be used for any data type that isn't a 
	 * structure, union, array, pointer, type definition, and whose size isn't in the 
	 * size/alignment map.
	 * @return the default alignment to be used if no other alignment can be 
	 * determined for a data type.
	 */
	@Override
	public int getDefaultAlignment() {
		return defaultAlignment;
	}

	/**
	 * Gets the default alignment to be used for a pointer that doesn't have size.
	 * @return the default alignment for a pointer
	 */
	@Override
	public int getDefaultPointerAlignment() {
		return defaultPointerAlignment;
	}

	/**
	 * Sets the maximum alignment value that is allowed by this data organization. When getting
	 * an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
	 * is returned, the data organization isn't specifically limited.
	 * @param absoluteMaxAlignment the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
	 */
	public void setAbsoluteMaxAlignment(int absoluteMaxAlignment) {
		this.absoluteMaxAlignment = absoluteMaxAlignment;
	}

	/**
	 * Sets the maximum useful alignment for the target machine
	 * @param machineAlignment the machine alignment
	 */
	public void setMachineAlignment(int machineAlignment) {
		this.machineAlignment = machineAlignment;
	}

	/**
	 * Sets the default alignment to be used for any data type that isn't a 
	 * structure, union, array, pointer, type definition, and whose size isn't in the 
	 * size/alignment map.
	 * @param defaultAlignment the default alignment to be used if no other alignment can be 
	 * determined for a data type.
	 */
	public void setDefaultAlignment(int defaultAlignment) {
		this.defaultAlignment = defaultAlignment;
	}

	/**
	 * Sets the default alignment to be used for a pointer that doesn't have size.
	 * @param defaultPointerAlignment the default alignment for a pointer
	 */
	public void setDefaultPointerAlignment(int defaultPointerAlignment) {
		this.defaultPointerAlignment = defaultPointerAlignment;
	}

	/**
	 * Gets the alignment that is defined for a data type of the indicated size if one is defined.
	 * @param size the size of the data type
	 * @return the alignment of the data type.
	 * @throws NoValueException if there isn't an alignment defined for the indicated size.
	 */
	@Override
	public int getSizeAlignment(int size) throws NoValueException {
		return sizeAlignmentMap.get(size);
	}

	/**
	 * Sets the alignment that is defined for a data type of the indicated size if one is defined.
	 * @param size the size of the data type
	 * @param alignment the alignment of the data type.
	 */
	public void setSizeAlignment(int size, int alignment) {
		sizeAlignmentMap.put(size, alignment);
	}

	/**
	 * Set the bitfield packing information associated with this data organization.
	 * @param bitFieldPacking bitfield packing information
	 */
	public void setBitFieldPacking(BitFieldPacking bitFieldPacking) {
		this.bitFieldPacking = bitFieldPacking;
	}

	/**
	 * Remove all entries from the size alignment map
	 */
	@Override
	public void clearSizeAlignmentMap() {
		sizeAlignmentMap.removeAll();
	}

	/**
	 * Gets the number of sizes that have an alignment specified.
	 * @return the number of sizes with an alignment mapped to them.
	 */
	@Override
	public int getSizeAlignmentCount() {
		return sizeAlignmentMap.size();
	}

	/**
	 * Gets the sizes that have an alignment specified.
	 * @return the sizes with alignments mapped to them.
	 */
	@Override
	public int[] getSizes() {
		int[] keys = sizeAlignmentMap.getKeys();
		Arrays.sort(keys);
		return keys;
	}

	/**
	 * Returns the best fitting integer C-type whose size is less-than-or-equal
	 * to the specified size.  "long long" will be returned for any size larger
	 * than "long long";
	 * @param size integer size
	 * @param signed if false the unsigned modifier will be prepended.
	 * @return the best fitting
	 */
	@Override
	public String getIntegerCTypeApproximation(int size, boolean signed) {
		String ctype = "long long";
		if (size <= 1) {
			ctype = "char";
		}
		else if (size <= getShortSize() && (getShortSize() != getIntegerSize())) {
			ctype = "short";
		}
		else if (size <= getIntegerSize()) {
			ctype = "int";
		}
		else if (size <= getLongSize()) {
			ctype = "long";
		}
		if (!signed) {
			ctype = "unsigned " + ctype;
		}
		return ctype;
	}

	@Override
	public int getAlignment(DataType dataType, int dtSize) {
		// Don't do alignment on dynamic data types.
		if (dataType instanceof Dynamic) {
//			throw new AssertException("Dynamic data types don't have an alignment. \"" + 
//					dataType.getName() + "\" is dynamic.");
			return 1;
		}
		// Typedef is aligned the same as its underlying data type is aligned.
		if (dataType instanceof TypeDef) {
			return getAlignment(((TypeDef) dataType).getBaseDataType(), dtSize);
		}
		// Array alignment is the alignment of its element data type.
		if (dataType instanceof Array) {
			DataType elementDt = ((Array) dataType).getDataType();
			int elementLength = ((Array) dataType).getElementLength();
			return getAlignment(elementDt, elementLength);
		}
		// Pointer alignment is based on its size or default pointer alignment if there is no size????
		if (dataType instanceof Pointer) {
			if (dtSize <= 0) {
				return getDefaultPointerAlignment();
			}
		}
		// Structure's or Union's alignment is a multiple of the least common multiple of
		// the components. It can also be adjusted by packing and alignment attributes.
		if (dataType instanceof Composite) {
			// IMPORTANT: composites are now responsible for computing their own alignment !!
			return ((Composite) dataType).getAlignment();
		}
		// Bit field alignment must be determined within the context of the containing structure.
		// See AlignedStructurePacker.
		if (dataType instanceof BitFieldDataType) {
			BitFieldDataType bitfieldDt = (BitFieldDataType) dataType;
			return getAlignment(bitfieldDt.getBaseDataType(), bitfieldDt.getBaseTypeSize());
		}
		// Otherwise get the alignment based on the size.
		if (sizeAlignmentMap.contains(dtSize)) {
			try {
				int sizeAlignment = sizeAlignmentMap.get(dtSize);
				return ((absoluteMaxAlignment == 0) || (sizeAlignment < absoluteMaxAlignment))
						? sizeAlignment
						: absoluteMaxAlignment;
			}
			catch (NoValueException e) {
				// Simply fall through to the default value.
			}
		}
		if (dataType instanceof Pointer) {
			return getDefaultPointerAlignment();
		}
		// Otherwise just assume the default alignment.
		return getDefaultAlignment();
	}

	@Override
	public boolean isForcingAlignment(DataType dataType) {
		return getForcedAlignment(dataType) > 0;
	}

	@Override
	public int getForcedAlignment(DataType dataType) {
		// Don't do forced alignment on dynamic data types.
		if (dataType instanceof Dynamic) {
			return 0;
		}
		// Typedef is aligned the same as its underlying data type is aligned.
		if (dataType instanceof TypeDef) {
			return getForcedAlignment(((TypeDef) dataType).getBaseDataType());
		}
		// Array alignment is the alignment of its element data type.
		if (dataType instanceof Array) {
			DataType elementDt = ((Array) dataType).getDataType();
			return getForcedAlignment(elementDt);
		}
		// We don't allow alignment attribute on pointers.
		if (dataType instanceof Pointer) {
			return 0;
		}

		// Structure's or Union's alignment is a multiple of the least common multiple of
		// the components. It can also be adjusted by packing and alignment attributes.
		if (dataType instanceof Composite) {
			// Check whether this composite forces the alignment.
			int forcedLCM = 0;
			Composite composite = (Composite) dataType;
			if (!composite.isInternallyAligned()) {
				return 0;
			}
			if (!composite.isDefaultAligned()) {
				int minimumAlignment = composite.getMinimumAlignment();
				forcedLCM = (minimumAlignment > 0) ? minimumAlignment : 0;
			}

			// Check each component and get the least common multiple of their forced minimum alignments.
			int componentForcedLCM = 0;
			for (DataTypeComponent dataTypeComponent : composite.getDefinedComponents()) {
				if (dataTypeComponent.isBitFieldComponent()) {
					continue;
				}
				DataType componentDt = dataTypeComponent.getDataType();
				int forcedAlignment = getForcedAlignment(componentDt);
				if (forcedAlignment > 0) {
					if (componentForcedLCM > 0) {
						componentForcedLCM =
							getLeastCommonMultiple(componentForcedLCM, forcedAlignment);
					}
					else {
						componentForcedLCM = forcedAlignment;
					}
				}
			}

			if (forcedLCM > 0) {
				if (componentForcedLCM > 0) {
					// Both this composite and one or more of its children force the alignment.
					return getLeastCommonMultiple(forcedLCM, componentForcedLCM);
				}
				// Children don't force alignment but this composite does.
				return forcedLCM;
			}
			// This composite's forced alignment is based only on its children's forced alignments.
			return componentForcedLCM;
		}
		// Otherwise not forcing alignment.
		return 0;
	}

	/**
	 * Determines the offset where the specified data type should be placed to be properly aligned.
	 * @param minimumOffset the minimum allowable offset where the data type can be placed.
	 * @param dataType the data type
	 * @param dtSize the data type's size
	 * @return the aligned offset for the data type
	 */
	@Override
	public int getAlignmentOffset(int minimumOffset, DataType dataType, int dtSize) {
		int alignment = getAlignment(dataType, dtSize);
		return getOffset(alignment, minimumOffset);
	}

	/**
	 * Determines the first offset that is equal to or greater than the minimum offset which 
	 * has the specified alignment.
	 * @param alignment the desired alignment
	 * @param minimumOffset the minimum offset
	 * @return the aligned offset
	 */
	public static int getOffset(int alignment, int minimumOffset) {
		return alignment + ((minimumOffset - 1) & ~(alignment - 1));
	}

	/**
	 * Determines the amount of padding that should be added to a structure at the indicated
	 * offset in order to get the next component (member) to be aligned with the specified 
	 * alignment within the structure.
	 * @param alignment the desired alignment
	 * @param offset the offset that the padding would be placed at to achieve the desired alignment.
	 * @return the padding needed at the offset.
	 */
	public static int getPaddingSize(int alignment, int offset) {
		return (alignment - (offset % alignment)) % alignment;
	}

	/**
	 * Determines the least (lowest) common multiple of two numbers.
	 * @param value1 the first number
	 * @param value2 the second number
	 * @return the least common multiple
	 */
	public static int getLeastCommonMultiple(int value1, int value2) {
		int gcd = getGreatestCommonDenominator(value1, value2);
		return (gcd != 0) ? ((value1 / gcd) * value2) : 0;
	}

	/**
	 * Determines the greatest common denominator of two numbers.
	 * @param value1 the first number
	 * @param value2 the second number
	 * @return the greatest common denominator
	 */
	public static int getGreatestCommonDenominator(int value1, int value2) {
		return (value2 != 0) ? getGreatestCommonDenominator(value2, value1 % value2) : value1;
	}

}
