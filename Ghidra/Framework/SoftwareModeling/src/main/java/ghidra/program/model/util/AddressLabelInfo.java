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
package ghidra.program.model.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

/**
 * <CODE>AddressLabelInfo</CODE> is a utility class for storing
 * an <CODE>Address</CODE> and a corresponding label or alias together.
 */
public class AddressLabelInfo implements Comparable<AddressLabelInfo> {
	private Address addr;
	private String label;
	private boolean isPrimary;
	private Namespace scope;
	private SourceType symbolSource;
	private boolean isEntry;
	private ProcessorSymbolType processorSymbolType;

	/**
	 * Constructs a new AddressLabelInfo object
	 * @param s symbol to initialize info from.
	 */
	public AddressLabelInfo(Symbol s) {
		this.addr = s.getAddress();
		this.label = s.getName();
		this.isPrimary = s.isPrimary();
		scope = s.getParentNamespace();
		symbolSource = s.getSource();
		isEntry = s.isExternalEntryPoint();
	}

	public AddressLabelInfo(Address addr, String label, boolean isPrimary, Namespace scope,
			SourceType symbolSource, boolean isEntry) {
		this(addr, label, isPrimary, scope, symbolSource, isEntry, null);
	}

	public AddressLabelInfo(Address addr, String label, boolean isPrimary, Namespace scope,
			SourceType symbolSource, boolean isEntry, ProcessorSymbolType type) {
		this.addr = addr;
		this.label = label;
		this.isPrimary = isPrimary;
		this.scope = scope;
		this.symbolSource = symbolSource;
		this.isEntry = isEntry;
		this.processorSymbolType = type;
	}

	public AddressLabelInfo(Address addr, String label, boolean isPrimary, SourceType symbolSource) {
		this(addr, label, isPrimary, null, symbolSource, false);
	}

	/**
	 * Constructs a new AddressLabelInfo object with only address information
	 * @param addr the address to store in this object
	 */
	public AddressLabelInfo(Address addr) {
		this(addr, null, false, null, SourceType.DEFAULT, false);
	}

	/**
	 * Returns the object's address.
	 */
	public final Address getAddress() {
		return addr;
	}

	/**
	 * Returns the object's label or alias.
	 */
	public final String getLabel() {
		return label;
	}

	/**
	 * Returns whether the object is the primary label at the address.
	 */
	public final boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * Returns the scope for the symbol.
	 */
	public Namespace getScope() {
		return scope;
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

	public SourceType getSource() {
		return symbolSource;
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
