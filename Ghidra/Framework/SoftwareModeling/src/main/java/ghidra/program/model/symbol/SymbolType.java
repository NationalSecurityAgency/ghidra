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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Class to represent the various types of Symbols.
 */
public abstract class SymbolType {

	public static final SymbolType LABEL = new SymbolType("Label", false, 0) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			if (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID &&
				program != parent.getSymbol().getProgram()) {
				return false;
			}
			// CODE symbol may not have an external function parent
			if (parent instanceof Function function) {
				return !function.isExternal();
			}
			return true;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress.isMemoryAddress() || symbolAddress.isExternalAddress();
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			if (sourceType != SourceType.DEFAULT) {
				return true;
			}
			return symbolAddress.isExternalAddress();
		}

		@Override
		public boolean allowsDuplicates() {
			return true;
		}

	};

	public static final SymbolType LIBRARY = new SymbolType("Library", false, 1) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			return parent.getID() == Namespace.GLOBAL_NAMESPACE_ID;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress == Address.NO_ADDRESS;
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return sourceType != SourceType.DEFAULT;
		}

	};

	public static final SymbolType NAMESPACE = new SymbolType("Namespace", true, 3) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			Symbol parentSymbol = parent.getSymbol();
			if (parentSymbol.isExternal()) {
				return false;
			}
			if (!parent.isGlobal() && program != parentSymbol.getProgram()) {
				return false;
			}
			return true;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress == Address.NO_ADDRESS;
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return sourceType != SourceType.DEFAULT;
		}

	};

	public static final SymbolType CLASS = new SymbolType("Class", true, 4) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			if (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID &&
				program != parent.getSymbol().getProgram()) {
				return false;
			}
			// CLASS can not be contained within a function
			while (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
				if (parent instanceof Function) {
					return false;
				}
				parent = parent.getParentNamespace();
			}
			return true;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress == Address.NO_ADDRESS;
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return sourceType != SourceType.DEFAULT;
		}

	};

	public static final SymbolType FUNCTION = new SymbolType("Function", true, 5) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {

			if (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID &&
				program != parent.getSymbol().getProgram()) {
				return false;
			}
			// FUNCTION can not be contained within a function
			while (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
				if (parent instanceof Function) {
					return false;
				}
				parent = parent.getParentNamespace();
			}
			return true;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress.isMemoryAddress() || symbolAddress.isExternalAddress();
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return true;
		}

		@Override
		public boolean allowsDuplicates() {
			return true;
		}
	};

	public static final SymbolType PARAMETER = new SymbolType("Parameter", false, 6) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			if (parent instanceof Function) {
				return program == parent.getSymbol().getProgram();
			}
			return false;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress.isVariableAddress();
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return true;
		}
	};

	public static final SymbolType LOCAL_VAR = new SymbolType("Local Var", false, 7) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			Symbol parentSymbol = parent.getSymbol();
			if (parentSymbol.isExternal()) {
				return false;
			}
			if (parent instanceof Function) {
				return program == parentSymbol.getProgram();
			}
			return false;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress.isVariableAddress();
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return true;
		}

	};

	public static final SymbolType GLOBAL_VAR = new SymbolType("Global Register Var", false, 8) {
		@Override
		public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
			return parent.getID() == Namespace.GLOBAL_NAMESPACE_ID;
		}

		@Override
		public boolean isValidAddress(Program program, Address symbolAddress) {
			return symbolAddress.isVariableAddress();
		}

		@Override
		public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
			return sourceType != SourceType.DEFAULT;
		}

	};

	public static final SymbolType GLOBAL =
		new SymbolType(GlobalNamespace.GLOBAL_NAMESPACE_NAME, true, -1) {
			@Override
			public boolean isValidParent(Program program, Namespace parent, Address symbolAddr) {
				return false;
			}

			@Override
			public boolean isValidAddress(Program program, Address symbolAddress) {
				return false;
			}

			@Override
			public boolean isValidSourceType(SourceType sourceType, Address symbolAddress) {
				return sourceType != SourceType.DEFAULT;
			}
		};

	private static final SymbolType[] types =
		{ LABEL, LIBRARY, null, NAMESPACE, CLASS, FUNCTION, PARAMETER, LOCAL_VAR, GLOBAL_VAR };

	private final String name;
	private final byte id;
	private final boolean isNamespace;

	private SymbolType(String name, boolean isNamespace, int id) {
		this.name = name;
		this.isNamespace = isNamespace;
		this.id = (byte) id;
	}

	/**
	 * Returns true if the given namespace is a valid parent for a symbol of this type
	 * if it has the given address and whether or not it is external.
	 * @param program the program to contain the symbol
	 * @param parent the namespace where a symbol will potentially be parented.
	 * @param symbolAddr the address of they symbol to be parented.
	 * @return true if the given namespace is a valid parent for a symbol if it has the
	 * given address and whether or not it is external.
	 */
	public abstract boolean isValidParent(Program program, Namespace parent, Address symbolAddr);

	/**
	 * Returns true if the given address is valid for this symbol type.
	 * @param program the program to test for a valid address.
	 * @param symbolAddress the address of the symbol to be tested.
	 * @return true if the given address is valid within the given program.
	 */
	public abstract boolean isValidAddress(Program program, Address symbolAddress);

	/**
	 * Returns true if the given SourceType is valid for this symbol type. (For example, Some symbols
	 * don't support the SymbolType.DEFAULT)
	 * @param sourceType the sourceType to test.
	 * @param symbolAddress the address of the symbol to be tested.
	 * @return true if the given SourceType is valid for this symbol type.
	 */
	public abstract boolean isValidSourceType(SourceType sourceType, Address symbolAddress);

	/**
	 * Returns true of this symbol type allows duplicate names.
	 * @return true of this symbol type allows duplicate names.
	 */
	public boolean allowsDuplicates() {
		return false;
	}

	/**
	 * {@return true if this symbol represents a namespace}
	 */
	public boolean isNamespace() {
		return isNamespace;
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * {@return the id of this symbol type}
	 */
	public byte getID() {
		return id;
	}

	/**
	 * Returns the SymbolType for the given id.
	 * @param id the id for the SymbolType to find.
	 * @return the SymbolType for the given id.
	 */
	public static SymbolType getSymbolType(int id) {
		if (id == -1) {
			return GLOBAL;
		}
		if (id < 0 || id >= types.length) {
			return null;
		}
		return types[id];
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (isNamespace ? 1231 : 1237);
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + id;
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
		if (!(obj instanceof SymbolType)) {
			return false;
		}
		SymbolType other = (SymbolType) obj;
		if (isNamespace != other.isNamespace) {
			return false;
		}
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		if (id != other.id) {
			return false;
		}
		return true;
	}

}
