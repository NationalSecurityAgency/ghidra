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
package ghidra.program.database.references;

import ghidra.program.model.symbol.SourceType;

class RefListFlagsV0 {

	// NOTE: Storage for SourceType has been expanded into upper zero-initialized bits 
	// with simple ProgramDB version change. 

	private static final int SOURCE_LOBIT = 0x01; // SourceType LO 1-bit
	private static final int IS_PRIMARY = 0x02;
	private static final int IS_OFFSET = 0x04;
	private static final int HAS_SYMBOL_ID = 0x08;
	private static final int IS_SHIFT = 0x10;
	private static final int SOURCE_HIBITS = 0x60; // SourceType HI 2-bits

	private static final int SOURCE_HIBIT = 0x20;

	private static final int SOURCE_LOBIT_SHIFT = 0;
	private static final int SOURCE_HIBITS_SHIFT = 5;

	private static final int MAX_SOURCE_VALUE = 7; // value limit based upon 3-bit storage capacity

	private int flags;

	RefListFlagsV0(byte flags) {
		this.flags = flags;
	}

	public RefListFlagsV0(boolean isPrimary, boolean isOffsetRef, boolean hasSymbolID,
			boolean isShiftRef, SourceType source) {
		flags = 0;

		// Get the storage ID to be used to encode source type
		// NOTE: RefListV0 uses a storage ID in some cases that differs from SourceType storage ID
		int sourceId = switch (source) {
			case DEFAULT -> 0;
			case ANALYSIS -> 2;
			default -> source.getStorageId();
		};

		// Encode SourceType value into split storage flags
		if (sourceId > MAX_SOURCE_VALUE) {
			throw new RuntimeException("Unsupported SourceType storage ID: " + sourceId);
		}
		int sourceTypeLoBit = (sourceId & 1) << SOURCE_LOBIT_SHIFT; // 1-bit
		int sourceTypeHiBits = (sourceId >>> 1) << SOURCE_HIBITS_SHIFT; // remaining hi-bits
		flags |= sourceTypeHiBits | sourceTypeLoBit;

		if (isPrimary)
			flags |= IS_PRIMARY;
		if (isOffsetRef)
			flags |= IS_OFFSET;
		if (hasSymbolID)
			flags |= HAS_SYMBOL_ID;
		if (isShiftRef)
			flags |= IS_SHIFT;
	}

	byte getValue() {
		return (byte) flags;
	}

	SourceType getSource() {

		// Decode storage ID from flags bits
		int sourceTypeLoBit = (flags & SOURCE_LOBIT) >>> SOURCE_LOBIT_SHIFT; // 1-bit
		int sourceTypeHiBits = (flags & SOURCE_HIBITS) >>> (SOURCE_HIBITS_SHIFT - 1); // remaining HI-bits
		int sourceTypeId = sourceTypeHiBits | sourceTypeLoBit;

		// NOTE: RefListV0 uses a storage ID in some cases that differs from SourceType storage ID
		return switch (sourceTypeId) {
			case 0 -> SourceType.DEFAULT;
			case 2 -> SourceType.ANALYSIS;
			default -> SourceType.getSourceType(sourceTypeId);
		};
	}

	public boolean hasSymbolID() {
		return (flags & HAS_SYMBOL_ID) != 0;
	}

	public boolean isShiftRef() {
		return (flags & IS_SHIFT) != 0;
	}

	public boolean isOffsetRef() {
		return (flags & IS_OFFSET) != 0;
	}

	public boolean isPrimary() {
		return (flags & IS_PRIMARY) != 0;
	}

	public void setPrimary(boolean isPrimary) {
		flags &= ~IS_PRIMARY;
		if (isPrimary) {
			flags |= IS_PRIMARY;
		}
	}

	public void setHasSymbolID(boolean hasSymbolID) {
		flags &= ~HAS_SYMBOL_ID;
		if (hasSymbolID) {
			flags |= HAS_SYMBOL_ID;
		}
	}

}
