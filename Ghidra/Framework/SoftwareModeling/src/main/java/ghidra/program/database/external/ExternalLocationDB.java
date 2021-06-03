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
package ghidra.program.database.external;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.database.symbol.SymbolDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;

public class ExternalLocationDB implements ExternalLocation {

	private static final char ORIGINAL_IMPORTED_DELIMITER = ',';
	private ExternalManagerDB extMgr;
	private SymbolDB symbol;

	/**
	 * Creates an externalLocationDB using a symbol
	 * at the same external space address.
	 * @param extMgr the ExternalManager.
	 * @param symbol the symbol for this external location.
	 * Typically, this will store the original mangled name when and if the original name
	 * is demangled.
	 */
	ExternalLocationDB(ExternalManagerDB extMgr, SymbolDB symbol) {
		this.extMgr = extMgr;
		this.symbol = symbol;
	}

	@Override
	public Symbol getSymbol() {
		return symbol;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getLibraryName()
	 */
	@Override
	public String getLibraryName() {
		Library library = getLibrary();
		return library != null ? library.getName() : "<UNKNOWN>";
	}

	private Library getLibrary() {
		Namespace parent = symbol.getParentNamespace();
		while (parent != null && !(parent instanceof Library)) {
			parent = parent.getParentNamespace();
		}
		return (Library) parent;

	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getParentNameSpace()
	 */
	@Override
	public Namespace getParentNameSpace() {
		return symbol.getParentNamespace();
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getParentName()
	 */
	@Override
	public String getParentName() {
		return symbol.getParentNamespace().getName();
	}

	long getExtNameID() {
		return symbol.getParentNamespace().getID();
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getLabel()
	 */
	@Override
	public String getLabel() {
		return symbol.getName();
	}

	@Override
	public String getOriginalImportedName() {
		return getExternalData3(symbol).getOriginalImportedName();
	}

	@Override
	public SourceType getSource() {
		return symbol.getSource();
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getAddress()
	 */
	@Override
	public Address getAddress() {
		return getExternalData3(symbol).getAddress(extMgr.getAddressMap().getAddressFactory());
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getExternalSpaceAddress()
	 */
	@Override
	public Address getExternalSpaceAddress() {
		return symbol.getAddress();
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(symbol.getName(true));
		if (getOriginalImportedName() != null) {
			builder.append(" (").append(getOriginalImportedName()).append(")");
		}
		return builder.toString();
	}

	@Override
	public boolean isFunction() {
		return symbol.getSymbolType() == SymbolType.FUNCTION;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#getDataType()
	 */
	@Override
	public DataType getDataType() {
		long dataTypeID = symbol.getSymbolData1();
		if (dataTypeID < 0) {
			return null;
		}
		return extMgr.getProgram().getDataTypeManager().getDataType(dataTypeID);
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalLocation#setDataType(ghidra.program.model.data.DataType)
	 */
	@Override
	public void setDataType(DataType dt) {
		long dataTypeID = extMgr.getProgram().getDataTypeManager().getResolvedID(dt);
		symbol.setSymbolData1(dataTypeID);

// TODO: change notification may be required
	}

	@Override
	public Function getFunction() {
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			return (Function) symbol.getObject();
		}
		return null;
	}

	@Override
	public Function createFunction() {
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			return getFunction();
		}
		Function function = extMgr.createFunction(this);
		symbol = (SymbolDB) function.getSymbol();
		return function;
	}

	/**
	 * Set the label and optional namespace associated with an external location.
	 * Any non-existing namespace will be created as a simple namespace within the associated
	 * library.
	 * @param label external location label.  The label may be qualified with a namespace
	 * and best effort will be used to parse it (see {@link SymbolPath}).
	 * If a namespace is not included within label, the current namespace will be preserved.
	 * @param source the source of this external symbol:
	 * Symbol.DEFAULT, Symbol.ANALYSIS, Symbol.IMPORTED, or Symbol.USER_DEFINED
	 * @throws InvalidInputException
	 * @see ghidra.program.model.symbol.ExternalLocation#setLabel(java.lang.String)
	 */
	void setLabel(String label, SourceType source) throws InvalidInputException {
		if (label == null) {
			setName(getLibrary(), null, SourceType.DEFAULT);
		}
		else if (label.indexOf(Namespace.DELIMITER) < 0) {
			// if label does not include namespace keep current namespace
			setName(symbol.getParentNamespace(), label, source);
		}
		else {
			SymbolPath symbolPath = new SymbolPath(label);
			Namespace namespace = NamespaceUtils.createNamespaceHierarchy(
				symbolPath.getParentPath(), getLibrary(), extMgr.getProgram(), source);
			setName(namespace, symbolPath.getName(), source);
		}
	}

	@Override
	public void setLocation(String label, Address addr, SourceType source)
			throws InvalidInputException {
		if (label != null && label.length() == 0) {
			label = null;
		}
		if (label == null && addr == null) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		if (addr != null && !addr.isMemoryAddress()) {
			throw new InvalidInputException("Invalid memory address");
		}
		setLabel(label, source);
		setAddress(addr);
	}

	@Override
	public void setAddress(Address address) throws InvalidInputException {
		String addressString = address != null ? address.toString() : null;
		if (addressString == null && getSource() == SourceType.DEFAULT) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		updateSymbolData3(symbol, getExternalData3(symbol).getOriginalImportedName(),
			addressString);
	}

	public void saveOriginalNameIfNeeded(Namespace oldNamespace, String oldName,
			SourceType oldSource) {

		boolean wasInLibrary = (oldNamespace instanceof Library);

		// if we don't have an original already set and it is an imported symbol, save it
		String originalImportedName = getOriginalImportedName();
		if (getLabel().equals(originalImportedName)) {
			setOriginalImportedName(symbol, null);
		}
		else if (wasInLibrary && getSource() != SourceType.DEFAULT &&
			oldSource == SourceType.IMPORTED && originalImportedName == null) {
			setOriginalImportedName(symbol, oldName);
		}
	}

	@Override
	public void setName(Namespace namespace, String newName, SourceType sourceType)
			throws InvalidInputException {

		try {
			if (!namespace.isExternal()) {
				throw new IllegalArgumentException("external namespace required");
			}
			if (newName == null || newName.length() == 0) {
				sourceType = SourceType.DEFAULT;
				String originalName = getOriginalImportedName();
				if (originalName != null) {
					newName = originalName;
					namespace = NamespaceUtils.getLibrary(namespace);
					sourceType = SourceType.IMPORTED;
				}
				else if (getAddress() == null) {
					throw new InvalidInputException(
						"Either an external label or address is required");
				}
			}
			else if (namespace instanceof Library && newName.equals(getOriginalImportedName())) {
				// preserve imported source if new name matches original imported name
				sourceType = SourceType.IMPORTED;
			}
			symbol.setNameAndNamespace(newName, namespace, sourceType);
		}
		catch (DuplicateNameException | CircularDependencyException e) {
			// Duplicate names are permitted and external locations do not support namespace behavior
			throw new AssertException("Unexpected exception", e);
		}
	}

	@Override
	public void restoreOriginalName() {
		String originalName = getOriginalImportedName();
		if (originalName == null) {
			return;
		}
		try {
			Library library = NamespaceUtils.getLibrary(symbol.getParentNamespace());
			symbol.setNameAndNamespace(originalName, library, SourceType.IMPORTED);
			setOriginalImportedName(symbol, null);
		}
		catch (CircularDependencyException | DuplicateNameException | InvalidInputException e) {
			throw new AssertException("Can't happen here", e);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((symbol == null) ? 0 : symbol.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ExternalLocationDB other = (ExternalLocationDB) obj;
		return symbol.equals(other.symbol);
	}

	@Override
	public boolean isEquivalent(ExternalLocation other) {
		if (other == null) {
			return false;
		}

		// first they must be the same of type of external locations
		if (isFunction() != other.isFunction()) {
			return false;
		}

		String name = getLabel();
		String originalImportName = getOriginalImportedName();
		String otherName = other.getLabel();
		String otherOriginalImportName = other.getOriginalImportedName();

		// if the original import names are not null and they match, this is probably the one since
		// the original import names are most likely mangled names and should be unique.
		if (originalImportName != null && originalImportName.equals(otherOriginalImportName)) {
			return true;
		}

		// Check if the name of one equals the original import name of the other.  The logic here
		// is that the originals are most likely unique so any match on the original is good.
		// For example, a case where one of the externalLocations is demangled and the other is not.

		if (otherName.equals(originalImportName)) {
			return true;
		}

		if (name.equals(otherOriginalImportName)) {
			return true;
		}

		if (originalImportName != null || otherOriginalImportName != null) {
			return false;
		}

		if (!getSymbol().getName(true).equals(other.getSymbol().getName(true))) {
			return false;
		}

		return SystemUtilities.isEqual(getAddress(), other.getAddress());

	}

	static ExternalData3 getExternalData3(SymbolDB extSymbol) {
		return new ExternalData3(extSymbol.getSymbolData3());
	}

	static void setOriginalImportedName(SymbolDB extSymbol, String name) {
		updateSymbolData3(extSymbol, name, getExternalData3(extSymbol).getAddressString());
	}

	static void updateSymbolData3(SymbolDB extSymbol, String originalImportedName,
			String addressString) {
		if (addressString == null && originalImportedName == null) {
			extSymbol.setSymbolData3(null);
		}
		StringBuilder buf = new StringBuilder();
		if (addressString != null) {
			buf.append(addressString);
		}
		if (originalImportedName != null) {
			buf.append(ORIGINAL_IMPORTED_DELIMITER);
			buf.append(originalImportedName);
		}
		extSymbol.setSymbolData3(buf.toString());
	}

	static class ExternalData3 {
		private String originalImportedName;
		private String addressString;

		ExternalData3(String data3) {
			if (data3 != null) {
				int indexOf = data3.indexOf(ORIGINAL_IMPORTED_DELIMITER);
				originalImportedName = indexOf >= 0 ? data3.substring(indexOf + 1) : null;
				addressString = indexOf >= 0 ? data3.substring(0, indexOf) : data3;
			}
		}

		public String getAddressString() {
			return addressString;
		}

		String getOriginalImportedName() {
			return originalImportedName;
		}

		Address getAddress(AddressFactory addrFactory) {
			if (addressString == null) {
				return null;
			}
			return addrFactory.getAddress(addressString);
		}

	}

}
