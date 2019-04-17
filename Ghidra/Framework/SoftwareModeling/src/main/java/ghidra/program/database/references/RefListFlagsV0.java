/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

	private static final int SOURCE_LOBIT = 0x01;
	private static final int IS_PRIMARY = 0x02;
	private static final int IS_OFFSET = 0x04;
	private static final int HAS_SYMBOL_ID = 0x08;
	private static final int IS_SHIFT = 0x10;
	private static final int SOURCE_HIBIT = 0x20;

	private int flags;

	RefListFlagsV0(byte flags) {
		this.flags = flags;
	}

	public RefListFlagsV0(boolean isPrimary, boolean isOffsetRef, boolean hasSymbolID,
			boolean isShiftRef, SourceType source) {
		flags = 0;
		if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) {
			flags |= SOURCE_LOBIT;
		}
		if (source == SourceType.ANALYSIS || source == SourceType.IMPORTED) {
			flags |= SOURCE_HIBIT;
		}
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
		boolean isLoBit = (flags & SOURCE_LOBIT) != 0;
		boolean isHiBit = (flags & SOURCE_HIBIT) != 0;
		if (isHiBit) {
			return isLoBit ? SourceType.IMPORTED : SourceType.ANALYSIS;
		}
		return isLoBit ? SourceType.USER_DEFINED : SourceType.DEFAULT;
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
