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

import ghidra.util.exception.AssertException;

/**
 * <code>AlignedComponentPacker</code> provides component packing support to the 
 * {@link AlignedStructurePacker}.
 */
class AlignedComponentPacker {

	private final DataOrganization dataOrganization;
	private final BitFieldPacking bitFieldPacking;
	private final int packValue; // structure packing value

	private int nextOrdinal;

	// We hang onto the imposed alignment and resulting offset for the last component
	// since the update of a zero-length bitfield must be deferred since it can be influenced 
	// by the next component and we only want to update it once.
	private int zeroAlignment; // imposed alignment on next component by zero bitfield

	private int lastAlignment; // identifies last component alignment

	// The groupOffset is used to identify start of zero-length bitfield as well
	// as fixed-length groups when groupSameSizeOnly is true.  Under other situations 
	// its value can not be relied upon.  -1 value indicates no active group.
	private int groupOffset = -1;

	private InternalDataTypeComponent lastComponent;

	private int defaultAlignment = 1;
	private boolean componentsChanged;

	AlignedComponentPacker(int packValue, DataOrganization dataOrganization) {
		this.dataOrganization = dataOrganization;
		this.bitFieldPacking = dataOrganization.getBitFieldPacking();
		this.packValue = packValue;
	}

	/**
	 * Add next component within structure.  All components should be added in sequence excluding
	 * DEFAULT components and any trailing flexible array component.
	 * @param dtc structure component
	 * @param isLastComponent true if dtc is the last component within the structure
	 */
	void addComponent(InternalDataTypeComponent dtc, boolean isLastComponent) {
		if (dtc.getDataType() == DataType.DEFAULT || dtc.isFlexibleArrayComponent()) {
			throw new IllegalArgumentException("unsupported component");
		}
		if (!packComponent(dtc)) {
			initGroup(dtc, isLastComponent);
		}
		lastComponent = dtc;
		++nextOrdinal;

		defaultAlignment = getComponentAlignmentLCM(defaultAlignment);
	}

	/**
	 * Determine if any component was modified during pack operation.
	 * @return true if one or more components were modified.
	 */
	boolean componentsChanged() {
		return componentsChanged;
	}

	/**
	 * Get the external structure alignment after all components have been packed.
	 * NOTE: This value does not factor in the affects of any trailing flexible array component
	 * which may exist or the alignment which may have been explicitly set on the structure.
	 * @return external alignment
	 */
	int getDefaultAlignment() {
		return defaultAlignment;
	}

	/**
	 * Get structure length after all components have been added.
	 * @return structure length
	 */
	int getLength() {
		if (lastComponent == null) {
			return 0;
		}
		int offset = 0;
		if (groupOffset >= 0 && lastComponent.isBitFieldComponent() &&
			bitFieldPacking.useMSConvention()) {
			// skip beyond unused bits based upon allocation size
			BitFieldDataType lastBitFieldDt = (BitFieldDataType) lastComponent.getDataType();
			offset = groupOffset + lastBitFieldDt.getBaseTypeSize();
		}
		else {
			offset = lastComponent.getOffset() + lastComponent.getLength();
			if (!bitFieldPacking.useMSConvention() && lastComponent.isZeroBitFieldComponent()) {
				// factor in trailing zero-length bitfield
				// TODO: does pack setting need to be considered?
				BitFieldDataType bitfieldDt = (BitFieldDataType) lastComponent.getDataType();
				int sizeAlignment = bitfieldDt.getBaseDataType().getAlignment();
				getBitFieldAlignment((BitFieldDataType) lastComponent.getDataType());
				offset = DataOrganizationImpl.getAlignedOffset(sizeAlignment, offset);
			}
		}
		return offset;
	}

	private int getBitFieldTypeSize(InternalDataTypeComponent dataTypeComponent) {
		DataType componentDt = dataTypeComponent.getDataType();
		if (componentDt instanceof BitFieldDataType) {
			return ((BitFieldDataType) componentDt).getBaseTypeSize();
		}
		throw new AssertException("expected bitfield component only");
	}

	private int getBitFieldAlignment(BitFieldDataType bitfieldDt) {

		if (!bitFieldPacking.useMSConvention() && packValue != CompositeInternal.DEFAULT_PACKING) {
			// GCC always uses 1 when packing regardless of pack value
			return 1;
		}

		return CompositeAlignmentHelper
				.getPackedAlignment(bitfieldDt.getBaseDataType().getAlignment(), packValue);
	}

	private boolean isIgnoredZeroBitField(BitFieldDataType zeroBitFieldDt) {
		if (!zeroBitFieldDt.isZeroLengthField()) {
			return false;
		}
		if (bitFieldPacking.useMSConvention()) {
			// TODO: verify when :0 is first component
			return lastComponent == null || !lastComponent.isBitFieldComponent();
		}
		return false;
	}

	private int getZeroBitFieldAlignment(BitFieldDataType zeroBitFieldDt, boolean isLastComponent) {

		if (isIgnoredZeroBitField(zeroBitFieldDt)) {
			return -1;
		}

		if (!bitFieldPacking.isTypeAlignmentEnabled()) {
			int zeroLengthBitFieldBoundary = bitFieldPacking.getZeroLengthBoundary();
			if (zeroLengthBitFieldBoundary > 0) {
				return zeroLengthBitFieldBoundary;
			}
			return 1;
		}

		int pack = packValue;
		if (!bitFieldPacking.useMSConvention() && !isLastComponent) {
			// GCC ignores pack value for :0 bitfield alignment but considers it when 
			// passing alignment along to structure
			pack = CompositeInternal.NO_PACKING;
		}

		return CompositeAlignmentHelper
				.getPackedAlignment(zeroBitFieldDt.getBaseDataType().getAlignment(), pack);
	}

	private void initGroup(InternalDataTypeComponent dataTypeComponent, boolean isLastComponent) {

		groupOffset = getLength();
		lastAlignment = 1;

		if (dataTypeComponent.isBitFieldComponent()) {

			BitFieldDataType zeroBitFieldDt = (BitFieldDataType) dataTypeComponent.getDataType();

			if (dataTypeComponent.isZeroBitFieldComponent()) {

				// An alignment of -1 indicates field is ignored
				int alignment = getZeroBitFieldAlignment(zeroBitFieldDt, isLastComponent);

				int zeroBitOffset = dataOrganization.isBigEndian() ? 7 : 0;
				if (zeroBitFieldDt.getBitOffset() != zeroBitOffset ||
					zeroBitFieldDt.getStorageSize() != 1) {
					try {
						BitFieldDataType packedBitFieldDt = new BitFieldDataType(
							zeroBitFieldDt.getBaseDataType(), 0, zeroBitOffset);
						dataTypeComponent.setDataType(packedBitFieldDt);
					}
					catch (InvalidDataTypeException e) {
						throw new AssertException("unexpected", e);
					}
					componentsChanged = true;
				}

				if (isLastComponent) {
					// special handling of zero-length bitfield when it is last component,
					// place on last byte within structure.
					int offset = groupOffset;
					int length = 1;
					if (lastComponent != null) {
						offset = groupOffset - 1; // lastComponent.getEndOffset();
					}
					updateComponent(dataTypeComponent, nextOrdinal, offset, length,
						alignment > 0 ? alignment : 1);
					groupOffset = -1;
				}
				else {
					// Avoid conveying zero alignment onto structure
					// Next component can influence alignment
					zeroAlignment = alignment;

					// NOTE: MSVC always conveys zero-length alignment
					if (bitFieldPacking.useMSConvention()) {
						lastAlignment = alignment;
					}

					// defer update of zero-length component and final determination of alignment.
				}
			}
			else {
				lastComponent = null; // first in allocation group
				alignAndPackBitField(dataTypeComponent); // relies on groupOffset when lastComponent==null
			}
		}
		else {
			// pack non-bitfield
			lastComponent = null; // first in allocation group
			alignAndPackNonBitfieldComponent(dataTypeComponent, groupOffset);
		}
	}

	/**
	 * Adjust lastComponent which must be a zero-length bitfield and its associated
	 * groupOffset based upon the adjusted alignment.
	 * @param ordinal component ordinal assignment
	 * @param minimumAlignment minimum alignment of component immediately after
	 * the zero-length component
	 */
	private void adjustZeroLengthBitField(int ordinal, int minimumAlignment) {

		int minOffset = DataOrganizationImpl.getAlignedOffset(minimumAlignment, groupOffset);
		int zeroAlignmentOffset = DataOrganizationImpl.getAlignedOffset(zeroAlignment, groupOffset);

		// Determine component offset of zero-length bitfield and the component
		// which immediately follows it.

		if (minOffset >= zeroAlignmentOffset) {
			// natural offset satisfies :0 alignment
			groupOffset = minOffset;
		}
		else {
			groupOffset = zeroAlignmentOffset;
		}

		updateComponent(lastComponent, ordinal, groupOffset, 1, minimumAlignment);
	}

	private boolean packComponent(InternalDataTypeComponent dataTypeComponent) {

		if (lastComponent == null || dataTypeComponent.isZeroBitFieldComponent()) {
			return false;
		}

		if (dataTypeComponent.isBitFieldComponent()) {

			if (!lastComponent.isZeroBitFieldComponent() && bitFieldPacking.useMSConvention()) {
				if (!lastComponent.isBitFieldComponent()) {
					return false; // can't pack bitfield with non-bitfield - start new group
				}
				if (getBitFieldTypeSize(dataTypeComponent) != getBitFieldTypeSize(lastComponent)) {
					return false; // bitfield base types differ in size - start new group
				}
			}

			alignAndPackBitField(dataTypeComponent);  // relies on lastComponent

			return true;
		}

		if (!lastComponent.isZeroBitFieldComponent() && bitFieldPacking.useMSConvention()) {
			return false; // start new group for non-bitfield
		}

		int offset;
		if (lastComponent.isZeroBitFieldComponent()) {
			offset = groupOffset;
		}
		else {
			offset = lastComponent.getOffset() + lastComponent.getLength();
		}

		alignAndPackNonBitfieldComponent(dataTypeComponent, offset);

		return true;
	}

	private void alignAndPackNonBitfieldComponent(InternalDataTypeComponent dataTypeComponent,
			int minOffset) {
		DataType componentDt = dataTypeComponent.getDataType();
		int dtSize = componentDt.getLength();
		if (dtSize <= 0) {
			dtSize = dataTypeComponent.getLength();
		}

		int alignment =
			CompositeAlignmentHelper.getPackedAlignment(componentDt.getAlignment(), packValue);

		int offset;
		if (lastComponent != null && lastComponent.isZeroBitFieldComponent()) {
			// adjust group alignment and offset of zero-length component (properly aligns groupOffset)
			adjustZeroLengthBitField(nextOrdinal - 1, alignment);
			offset = groupOffset;
		}
		else {
			offset = DataOrganizationImpl.getAlignedOffset(alignment, minOffset);
			if (lastComponent == null) {
				groupOffset = offset; // establish corrected group offset after alignment
			}
		}

		updateComponent(dataTypeComponent, nextOrdinal, offset, dtSize, alignment);
	}

	private void alignAndPackBitField(InternalDataTypeComponent dataTypeComponent) {

		BitFieldDataType bitfieldDt = (BitFieldDataType) dataTypeComponent.getDataType();

		if (lastComponent != null && lastComponent.isZeroBitFieldComponent()) {
			int alignment = bitFieldPacking.useMSConvention() ? getBitFieldAlignment(bitfieldDt)
					: zeroAlignment;
			adjustZeroLengthBitField(nextOrdinal - 1, alignment);
		}

		int offset;
		int bitsConsumed;

		// update lastAlignment to be conveyed onto structure alignment
		int alignment = CompositeAlignmentHelper.getPackedAlignment(
			bitfieldDt.getPrimitiveBaseDataType().getAlignment(), packValue);

		// Set conveyed alignment early since bitfield alignment may be reduced below
		lastAlignment = Math.max(alignment, lastAlignment);

		if (lastComponent == null) {
			offset = DataOrganizationImpl.getAlignedOffset(alignment, groupOffset);
			bitsConsumed = 0;
			groupOffset = offset; // establish corrected group offset after alignment
		}
		else if (lastComponent.isZeroBitFieldComponent()) {
			// - assume lastComponent (zero-length bitfield) has already been adjusted and updated
			// - first bitfield following a :0 bitfield which has already been adjusted by packComponent
			// - groupOffset contains aligned offset to be used
			offset = groupOffset;
			bitsConsumed = 0;
		}
		else {

			// follow normal rule for aligning bitfield which may differ from the alignment
			// imparted onto structure via lastAlignment
			alignment = getBitFieldAlignment(bitfieldDt);

			BitFieldDataType lastBitfieldDt = null;
			if (lastComponent.isBitFieldComponent()) {

				// assume lastComponent bit-field has already been packed and has correct bit-offset

				lastBitfieldDt = (BitFieldDataType) lastComponent.getDataType();
				offset = lastComponent.getEndOffset();
				if (dataOrganization.isBigEndian()) {
					// filled left-to-right
					bitsConsumed = 8 - lastBitfieldDt.getBitOffset();
					// bitsConsumed range: 1 to 8, where 8 indicates last byte fully consumed
				}
				else { // little-endian
						// filled right-to-left (viewed from normalized form after byte-swap)
					bitsConsumed =
						(lastBitfieldDt.getBitSize() + lastBitfieldDt.getBitOffset()) % 8;
					// bitsConsumed range: 0 to 7, where 0 indicates last byte fully consumed
				}
				if (bitsConsumed == 8 || bitsConsumed == 0) {
					// last byte is fully consumed
					bitsConsumed = 0;
					++offset;
				}

			}
			else {
				// previous field is non-bitfield
				offset = lastComponent.getOffset() + lastComponent.getLength();
				bitsConsumed = 0;
			}

			int byteSize = (bitfieldDt.getBitSize() + bitsConsumed + 7) / 8;
			int endOffset = offset + byteSize - 1;

			if (offset % alignment != 0 || byteSize > bitfieldDt.getBaseTypeSize()) {
				// offset is not an aligned offset (which may be OK when packing with lastComponent)
				int alignedBaseOffset =
					DataOrganizationImpl.getAlignedOffset(alignment, offset) - alignment;
				if (endOffset >= alignedBaseOffset + bitfieldDt.getBaseTypeSize()) {
					// skip ahead to next aligned offset
					offset = DataOrganizationImpl.getAlignedOffset(alignment, offset + 1);
					endOffset = offset + byteSize - 1;
					bitsConsumed = 0;
				}
			}

			// establish new groupOffset if necessary
			if (groupOffset >= 0 && lastBitfieldDt != null &&
				endOffset >= (groupOffset + lastBitfieldDt.getBaseTypeSize())) {
				groupOffset = bitFieldPacking.useMSConvention() ? offset : -1;
			}
		}

		int byteSize = setBitFieldDataType(dataTypeComponent, bitfieldDt, bitsConsumed);

		updateComponent(dataTypeComponent, nextOrdinal, offset, byteSize, alignment);
	}

	private int setBitFieldDataType(InternalDataTypeComponent dataTypeComponent,
			BitFieldDataType currentBitFieldDt, int bitsConsumed) {
		int byteSize = (currentBitFieldDt.getBitSize() + bitsConsumed + 7) / 8;
		int bitOffset;
		if (dataOrganization.isBigEndian()) {
			// filled left-to-right
			bitOffset = (byteSize * 8) - currentBitFieldDt.getBitSize() - bitsConsumed;
		}
		else { // little-endian
				// filled right-to-left (viewed from normalized form after byte-swap)
			bitOffset = bitsConsumed;
		}

		if (bitOffset != currentBitFieldDt.getBitOffset()) {
			try {
				BitFieldDataType packedBitFieldDt =
					new BitFieldDataType(currentBitFieldDt.getBaseDataType(),
						currentBitFieldDt.getDeclaredBitSize(), bitOffset);
				dataTypeComponent.setDataType(packedBitFieldDt);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException("unexpected", e);
			}
			componentsChanged = true;
		}
		return byteSize;
	}

	private void updateComponent(InternalDataTypeComponent dataTypeComponent, int ordinal,
			int offset, int length, int alignment) {

		if (ordinal != dataTypeComponent.getOrdinal() || offset != dataTypeComponent.getOffset() ||
			length != dataTypeComponent.getLength()) {

			dataTypeComponent.update(ordinal, offset, length);
			componentsChanged = true;
		}

		lastAlignment = Math.max(lastAlignment, alignment);
	}

	private int getComponentAlignmentLCM(int allComponentsLCM) {

		if (lastAlignment == 0) {
			return lastAlignment;
		}

		// factor in pack value, which may have been ignored when aligning component
		int alignment = lastAlignment;
		if (packValue > 0 && alignment > packValue) {
			alignment = packValue;
		}
		return DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM, alignment);
	}

}
