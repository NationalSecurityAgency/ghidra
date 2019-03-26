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
import ghidra.program.model.listing.Function;

import java.math.BigInteger;

public class DisplayableVariableOffset implements DisplayableOffset {

	protected final Function function;
	protected Address parameterAddress;
	protected long offset;
	protected BigInteger offsetAsBigInteger;

	public DisplayableVariableOffset(Function function, Address parameterAddress) {
		this.function = function;
		this.parameterAddress = parameterAddress;
		offset = (parameterAddress != null) ? parameterAddress.getOffset() : 0;
		offsetAsBigInteger =
			(parameterAddress != null) ? parameterAddress.getOffsetAsBigInteger() : null;
	}

	@Override
	public Address getAddress() {
		return parameterAddress;
	}

	public long getOffset() {
		return offset;
	}

	public BigInteger getOffsetAsBigInteger() {
		return offsetAsBigInteger;
	}

	public String getDisplayString() {
		if (parameterAddress == null || parameterAddress == Address.NO_ADDRESS) {
			return NO_OFFSET;
		}
		return parameterAddress.toString();
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
		if (parameterAddress == null) {
			return (otherAddress == null) ? 0 : -1;
		}
		if (otherAddress == null) {
			return 1;
		}
		return parameterAddress.compareTo(otherAddress);
	}

}
