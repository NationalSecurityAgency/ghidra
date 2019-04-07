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
package ghidra.program.util.string;

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

public class FoundString implements Comparable<FoundString> {
	public enum DefinedState {
		NOT_DEFINED, DEFINED, PARTIALLY_DEFINED, CONFLICTS
	}

	private Address address;
	private int length;
	private DataType stringDataType;
	private DefinedState definedState = DefinedState.NOT_DEFINED;

	public FoundString(Address address, int length, DataType stringDataType) {
		this(address, length, stringDataType, DefinedState.NOT_DEFINED);
	}

	public FoundString(Address address, int length, DataType stringDataType,
			DefinedState definedState) {
		this.length = length;
		this.stringDataType = stringDataType;
		this.address = address;
		this.definedState = definedState;
	}

	public int getLength() {
		return length;
	}

	public Address getAddress() {
		return address;
	}

	public Address getEndAddress() {
		return address.add(length - 1);
	}

	public boolean isUndefined() {
		return definedState == DefinedState.NOT_DEFINED;
	}

	public boolean isDefined() {
		return definedState == DefinedState.DEFINED;
	}

	public boolean isPartiallyDefined() {
		return definedState == DefinedState.PARTIALLY_DEFINED;
	}

	public boolean conflicts() {
		return definedState == DefinedState.CONFLICTS;
	}

	public String getString(Memory memory) {
		MemBuffer membuf = new DumbMemBufferImpl(memory, address);
		return StringDataInstance.getStringDataInstance(stringDataType, membuf,
			SettingsImpl.NO_SETTINGS, length).getStringValue();
	}

	public StringDataInstance getDataInstance(Memory memory) {
		MemBuffer membuf = new DumbMemBufferImpl(memory, address);
		return new StringDataInstance(stringDataType, SettingsImpl.NO_SETTINGS, membuf, length);
	}

	public void setDefinedState(DefinedState newState) {
		definedState = newState;
	}

	public DefinedState getDefinedState() {
		return definedState;
	}

	public boolean isPascall() {
		return ((stringDataType instanceof PascalStringDataType) ||
			(stringDataType instanceof PascalString255DataType) ||
			(stringDataType instanceof PascalUnicodeDataType));
	}

	public DataType getDataType() {
		return stringDataType;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public void setLength(int length) {
		this.length = length;
	}

	@Override
	public int hashCode() {
		return address.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj.getClass() != getClass()) {
			return false;
		}
		FoundString other = (FoundString) obj;
		return address.equals(other.getAddress());

	}

	@Override
	public int compareTo(FoundString other) {
		return address.compareTo(other.address);
	}

	public int getStringLength(Memory mem) {
		StringDataInstance stringDataInstance = getDataInstance(mem);
		return stringDataInstance.getStringLength();
	}

	@Override
	public String toString() {
		return "@" + address + ", length=" + length + ", state=" + definedState;
	}
}
