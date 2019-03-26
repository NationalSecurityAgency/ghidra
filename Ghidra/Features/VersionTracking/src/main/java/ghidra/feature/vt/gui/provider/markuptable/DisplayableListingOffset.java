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
package ghidra.feature.vt.gui.provider.markuptable;

import ghidra.feature.vt.gui.editors.DisplayableOffset;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.math.BigInteger;

public class DisplayableListingOffset implements DisplayableOffset {

	protected final Program program;
	protected Address address;
	protected long offset;
	protected BigInteger offsetAsBigInteger;

	public DisplayableListingOffset(Program program, Address currentAddress) {
		this.program = program;
		this.address = currentAddress;
		if (currentAddress == null || currentAddress == Address.NO_ADDRESS) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(currentAddress);
		Address startAddress;
		if (function != null) {
			startAddress = function.getEntryPoint();
		}
		else {
			CodeUnit codeUnit = program.getListing().getCodeUnitContaining(currentAddress);
			startAddress = codeUnit.getMinAddress();
		}
		long startOffset = startAddress.getOffset();
		BigInteger startOffsetAsBigInteger = startAddress.getOffsetAsBigInteger();
		long currentOffset = currentAddress.getOffset();
		BigInteger currentOffsetAsBigInteger = currentAddress.getOffsetAsBigInteger();
		offset = currentOffset - startOffset;
		offsetAsBigInteger = currentOffsetAsBigInteger.subtract(startOffsetAsBigInteger);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	public long getOffset() {
		return offset;
	}

	public BigInteger getOffsetAsBigInteger() {
		return offsetAsBigInteger;
	}

	public String getDisplayString() {
		if (address == null || address == Address.NO_ADDRESS) {
			return NO_OFFSET;
		}
		return offsetAsBigInteger.toString();
	}

	@Override
	public String toString() {
		return getDisplayString();
	}

	@Override
	public int compareTo(DisplayableOffset otherDisplayableOffset) {
		if (otherDisplayableOffset == null) {
			return 1;
		}
		Address otherAddress = otherDisplayableOffset.getAddress();
		if (address == null || address == Address.NO_ADDRESS) {
			return (otherAddress == null || otherAddress == Address.NO_ADDRESS) ? 0 : -1;
		}
		if (otherAddress == null || otherAddress == Address.NO_ADDRESS) {
			return 1;
		}
		return offsetAsBigInteger.compareTo(otherDisplayableOffset.getOffsetAsBigInteger());
	}

}
