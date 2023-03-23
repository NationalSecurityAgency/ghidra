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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.util.ProcessorSymbolType;

/**
 * <CODE>AddressLabelInfo</CODE> is a utility class for storing
 * an <CODE>Address</CODE> together with a corresponding language-defined 
 * label or alias that is within the global namespace which is
 * established with a SourceType of IMPORTED within a program.
 */
public class AddressLabelInfo implements Comparable<AddressLabelInfo> {
	private Address addr;
	private Address endAddr;
	private String label;
	private boolean isPrimary;
	private boolean isEntry;
	private ProcessorSymbolType processorSymbolType;
	private int sizeInBytes;
	private Boolean isVolatile;
	
	/**
	 * Constructor for class AddressLabelInfo
	 * 
	 * @param	addr			Address object that describes the memory address
	 * @param	sizeInBytes		Integer describing the Size in bytes that the label applies to.
	 * @param	label			String label or alias for the Address
	 * @param 	isPrimary		boolean describes if this object is the primary label for the Address 'addr'
	 * @param	isEntry			boolean describes if this object is an entry label for the Address 'addr'
	 * @param	type			ProcessorSymbolType the type of symbol
	 * @param	isVolatile		Boolean describes if the memory at this address is volatile
	 */
	public AddressLabelInfo(Address addr, Integer sizeInBytes, String label, boolean isPrimary, 
			boolean isEntry, ProcessorSymbolType type, Boolean isVolatile) throws AddressOverflowException {
		this.addr = addr;
		if ( sizeInBytes == null || sizeInBytes <= 0 ) {
			// Default size in addressable units
			this.sizeInBytes = addr.getAddressSpace().getAddressableUnitSize();
		} else {
			this.sizeInBytes = sizeInBytes;
		}
		this.endAddr = this.addr.addNoWrap(this.sizeInBytes-1);
		this.label = label;
		this.isPrimary = isPrimary;
		this.isEntry = isEntry;
		this.processorSymbolType = type;
		this.isVolatile = isVolatile;
	}

	/**
	 * Returns the object's address.
	 */
	public final Address getAddress() {
		return addr;
	}
	
	/**
	 * Returns the object's end address.
	 */
	public final Address getEndAddress() {
		return endAddr;
	}
	
	/**
	 * Returns the object's label or alias.
	 */
	public final String getLabel() {
		return label;
	}

	/**
	 * Returns the object's size in bytes. Always non-zero positive value and defaults to 
	 * addressable unit size of associated address space.
	 */
	public final int getByteSize() {
		return sizeInBytes;
	}
	
	/**
	 * Returns whether the object is the primary label at the address.
	 */
	public final boolean isPrimary() {
		return isPrimary;
	}
	
	/**
	 * Returns whether the object is volatile.
	 * Boolean.False when the address is explicitly not volatile.
	 * Boolean.True when the address is volatile.
	 * NULL when the volatility is not defined at this address.
	 */
	public final Boolean isVolatile() {
		return isVolatile;
	}

	/**
	 * Returns the type of processor symbol (if this was defined by a pspec) or null if this
	 * is not a processor symbol or it was not specified in the pspec file.  It basically allows
	 * a pspec file to give more information about a symbol such as if code or a code pointer is
	 * expected to be at the symbol's address.
	 * @return the ProcesorSymbolType if it has one.
	 */
	public ProcessorSymbolType getProcessorSymbolType() {
		return processorSymbolType;
	}

	@Override
	public int compareTo(AddressLabelInfo info) {
		if (info == null) {
			return 1;
		}

		String addrStr = info.getAddress().toString();
		String thisStr = getAddress().toString();
		int stringCompare = thisStr.compareTo(addrStr);

		if (stringCompare != 0) {
			return stringCompare;
		}

		String addrLabel = info.getLabel();
		String thisLabel = getLabel();

		if (addrLabel == null) {
			if (thisLabel == null) {
				return 0;
			}
			return 1;
		}
		if (thisLabel == null) {
			return -1;
		}
		return thisLabel.compareTo(addrLabel);
	}

	public boolean isEntry() {
		return isEntry;
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("LABEL INFO NAME=");
		buf.append(label);
		buf.append(", ");
		buf.append("ADDR=" + addr);
		buf.append(", ");
		buf.append("isEntry = " + isEntry);
		buf.append(", ");
		buf.append("type = " + processorSymbolType);
		return buf.toString();
	}
}
