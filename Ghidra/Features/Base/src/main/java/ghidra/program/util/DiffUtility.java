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
package ghidra.program.util;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

/**
 * The <CODE>DiffUtility</CODE> class provides static methods for getting and
 * creating an object in one program based on an object from another program.
 */
public class DiffUtility extends SimpleDiffUtility {

	/**
	 * Determines the memory address in the other program that is compatible with the 
	 * specified address.
	 * @param memoryAddress the memory address to be converted
	 * @param otherProgram target program which corresponds to the returned address.
	 * @return the memory address derived from the other program or null if one cannot
	 * be determined.
	 */
	public static Address getCompatibleMemoryAddress(Address memoryAddress, Program otherProgram) {
		if ((memoryAddress != null) && memoryAddress.isMemoryAddress()) {
			return translateMemoryAddress(memoryAddress, otherProgram, true);
		}
		return null;
	}

	/**
	 * Convert an address-set from one program to a compatible address-set in the 
	 * specified otherProgram.  Those regions which can not be mapped will be eliminated 
	 * from the new address-set.  Only memory addresses will be considered.
	 * @param set address-set corresponding to program
	 * @param otherProgram target program which corresponds to the returned address set.
	 * @return translated address-set
	 */
	public static AddressSet getCompatibleAddressSet(AddressSetView set, Program otherProgram) {
		AddressSet otherSet = new AddressSet();
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			AddressRange compatibleAddressRange = getCompatibleAddressRange(range, otherProgram);
			if (compatibleAddressRange != null) {
				otherSet.add(compatibleAddressRange);
			}
		}
		return otherSet;
	}

	/**
	 * Reduce an address-set from one program to the set of addresses that are incompatible with
	 * the specified otherProgram.
	 * @param set address-set corresponding to one program
	 * @param otherProgram the addresses are incompatible with this other program.
	 * @return incompatible address-set
	 */
	public static AddressSet getNonCompatibleAddressSet(AddressSetView set, Program otherProgram) {
		AddressSet nonCompatibleSet = new AddressSet();
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			AddressRange compatibleAddressRange = getCompatibleAddressRange(range, otherProgram);
			if (compatibleAddressRange == null) {
				nonCompatibleSet.add(range);
			}
		}
		return nonCompatibleSet;
	}

	/**
	 * Convert an address range from one program to a compatible address range in the 
	 * specified otherProgram.  Only memory addresses will be considered.
	 * If the entire range cannot be converted then null is returned.
	 * @param range address range to convert
	 * @param otherProgram target program which corresponds to the returned address range.
	 * @return translated address range or null if a compatible range could not be 
	 * determined in the other program.
	 */
	public static AddressRange getCompatibleAddressRange(AddressRange range, Program otherProgram) {
		Address nextMin = range.getMinAddress();
		Address nextMax = range.getMaxAddress();
		Address newMinAddress = translateMemoryAddress(nextMin, otherProgram, false);
		Address newMaxAddress = translateMemoryAddress(nextMax, otherProgram, true);
		try {
//			while (newMinAddress == null) {
//				nextMin = nextMin.add(1L);
//				int compareMinToMax = nextMin.compareTo(nextMax);
//				if (compareMinToMax > 0) {
//					break;
//				}
//				newMinAddress = translateMemoryAddress(nextMin, otherProgram, true);
//				if (compareMinToMax == 0) {
//					break;
//				}
//			}
			while (newMaxAddress == null && nextMin != null) {
				nextMax = nextMax.subtract(1L);
				int compareMaxToMin = nextMax.compareTo(nextMin);
				if (compareMaxToMin < 0) {
					break;
				}
				newMaxAddress = translateMemoryAddress(nextMax, otherProgram, true);
				if (compareMaxToMin == 0) {
					break;
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			// Won't be able to add 1 at end of block or subtract 1 at start of block.
		}
		if (newMinAddress == null || newMaxAddress == null ||
			newMinAddress.getOffset() > newMaxAddress.getOffset()) {
			return null;
		}
		return new AddressRangeImpl(newMinAddress, newMaxAddress);
	}

	/**
	 * Compare any two addresses from two different programs.
	 * @param program1
	 * @param addr1
	 * @param program2
	 * @param addr2
	 * @return
	 */
	public static int compare(Program program1, Address addr1, Program program2, Address addr2) {
		Address translatedAddr = getCompatibleAddress(program1, addr1, program2);
		if (translatedAddr != null) {
			if (addr2 != null) {
				return translatedAddr.compareTo(addr2);
			}
			return 1;
		}
		if (addr2 == null) {
			return 0;
		}
		return -1;
	}

	/**
	 * Given a namespace, get the corresponding namespace from the 
	 * specified otherProgram.  The return namespace body may be different.
	 * @param namespace namespace to look for
	 * @param otherProgram other program
	 * @return corresponding namespace for otherProgram or null if no such namespace exists.
	 */
	public static Namespace getNamespace(Namespace namespace, Program otherProgram) {
		Symbol s = getSymbol(namespace.getSymbol(), otherProgram);
		return s != null ? (Namespace) s.getObject() : null;
	}

	/**
	 * Given a namespace, create the corresponding namespace in the 
	 * specified otherProgram. If a corresponding namespace already exists, it is returned.
	 * The return namespace body may be different.
	 * @param program program which contains the specified namespace instance
	 * @param namespace namespace to look for
	 * @param otherProgram other program
	 * @return corresponding namespace for otherProgram or null if no such namespace exists.
	 * @throws InvalidInputException if the namespace's name or path is not valid.
	 * @throws DuplicateNameException if the namespace's name or path cannot be created
	 * due to a conflict with another namespace or symbol.
	 */
	public static Namespace createNamespace(Program program, Namespace namespace,
			Program otherProgram) throws InvalidInputException, DuplicateNameException {
		if (namespace == null) {
			return otherProgram.getGlobalNamespace();
		}
		Symbol otherNamespaceSymbol = getSymbol(namespace.getSymbol(), otherProgram);
		if (otherNamespaceSymbol != null) {
			return (Namespace) otherNamespaceSymbol.getObject();
		}
		Namespace parentNamespace = namespace.getParentNamespace();
		Namespace otherParentNamespace = createNamespace(program, parentNamespace, otherProgram);
		SourceType source = namespace.getSymbol().getSource();
		if (namespace instanceof Library) {
			return otherProgram.getSymbolTable().createExternalLibrary(namespace.getName(), source);
		}
		else if (namespace instanceof GhidraClass) {
			return otherProgram.getSymbolTable()
				.createClass(otherParentNamespace, namespace.getName(), source);
		}
		return otherProgram.getSymbolTable()
			.createNameSpace(otherParentNamespace, namespace.getName(), source);
	}

//	/**
//	 * Given a symbol for a specified program, get the corresponding symbol from the 
//	 * specified otherProgram.
//	 * @param program program which contains the specified symbol instance
//	 * @param p2Symbol symbol to look for
//	 * @param otherProgram other program
//	 * @return corresponding symbol for otherProgram or null if no such symbol exists.
//	 */
//	public static Symbol getSymbol(AddressTranslator p2ToP1Translator, Symbol p2Symbol) {
//		
//		if (p2Symbol == null) {
//			return null;
//		}
//		Program otherProgram = p2ToP1Translator.getDestinationProgram();
//		SymbolType st = p2Symbol.getSymbolType();
//		if (st == SymbolType.GLOBAL) {
//			return otherProgram.getGlobalNamespace().getSymbol();
//		}
//		if (st == SymbolType.FUNCTION) {
//			Function func = (Function) p2Symbol.getObject();
//			Address p1Entry = p2ToP1Translator.getAddress(func.getEntryPoint());
//			if (p1Entry == null) {
//				return null;
//			}
//			func = otherProgram.getFunctionManager().getFunctionAt(p1Entry);
//			return func != null ? func.getSymbol() : null;
//		}
//		
//		SymbolTable otherSymTable = otherProgram.getSymbolTable();
//		Address addr2 = p2Symbol.getAddress();
//		if (addr2.isVariableAddress()) {
//			Variable var2 = (Variable) p2Symbol.getObject();
//			Symbol otherFuncSym = getSymbol(p2ToP1Translator, p2Symbol.getParentSymbol());
//			Address storeAddr = p2ToP1Translator.getAddress(var2.getStorageAddress());
//			return getVariableSymbol(otherSymTable, var2, otherFuncSym,	storeAddr);
//		}
//		
//		Symbol parent1 = getSymbol(p2ToP1Translator, p2Symbol.getParentSymbol());
//		if (parent1 == null) {
//			return null;
//		}
//		Namespace namespace = (Namespace)parent1.getObject();
//		String name2 = p2Symbol.getName();
//		
//		AddressSpace addrSpace = addr2.getAddressSpace();
//		if (addrSpace.getType() == AddressSpace.TYPE_NONE || addr2.isExternalAddress()) {
//			Symbol s = otherSymTable.getSymbol(name2, namespace);
//			return (s != null && st == s.getSymbolType()) ? s : null;
//		}
//
//		if (addr2.isMemoryAddress()) {
//			Symbol s = otherSymTable.getSymbol(name2, addr2, namespace);
//			return (s != null && st == s.getSymbolType()) ? s : null;
//		}
//
//		return null;
//	}

	/**
	 * Determine if the specified variables have overlapping storage.
	 * Variable storage check includes dynamically mapped storage for parameters.  This method
	 * should not be used with caution if both arguments are parameters which use dynamically 
	 * mapped storage.
	 * @param var1
	 * @param var2
	 * @return true if variables overlap, else false
	 */
	public static boolean variableStorageOverlaps(Variable var1, Variable var2) {
		Program program1 = var1.getFunction().getProgram();
		Program program2 = var2.getFunction().getProgram();
		VariableStorage storage =
			getCompatibleVariableStorage(program1, var1.getVariableStorage(), program2);
		if (storage == null || storage.isBadStorage()) {
			return false;
		}
		return storage.intersects(var2.getVariableStorage());
	}

	/**
	 * Determine if the specified variables have exactly the same storage.  This method
	 * should not be used with caution if both arguments are parameters which use dynamically 
	 * mapped storage.
	 * @param var1
	 * @param var2
	 * @return true if variables have matching storage, else false
	 */
	public static boolean variableStorageMatches(Variable var1, Variable var2) {
		Program program1 = var1.getFunction().getProgram();
		Program program2 = var2.getFunction().getProgram();
		VariableStorage storage =
			getCompatibleVariableStorage(program1, var1.getVariableStorage(), program2);
		if (storage == null || storage.isBadStorage()) {
			return false;
		}
		return storage.equals(var2.getVariableStorage());
	}

	/**
	 * Given a function, get the corresponding function from the 
	 * specified otherProgram.  Function matchup is done based upon 
	 * function entry point only.  The function bodies may be different.
	 * @param function function to look for
	 * @param otherProgram other program
	 * @return corresponding function for otherProgram or null if no such function exists.
	 */
	public static Function getFunction(Function function, Program otherProgram) {
		return (Function) getNamespace(function, otherProgram);
	}

	/**
	 * Given a reference for a specified program, get the corresponding reference from the 
	 * specified otherProgram.  A Non-memory reference is considered a suitable reference
	 * for returning if its destination address is from the same address space (i.e., stack, 
	 * register, etc.) 
	 * @param program program which contains the specified reference instance
	 * @param ref reference to look for
	 * @param otherProgram other program
	 * @return corresponding reference for otherProgram or null if no such reference exists.
	 */
	public static Reference getReference(Program program, Reference ref, Program otherProgram) {
		Address fromAddr = getCompatibleAddress(program, ref.getFromAddress(), otherProgram);
		if (fromAddr == null) {
			return null;
		}
		if (ref.isMemoryReference()) {
			Address toAddr = getCompatibleAddress(program, ref.getToAddress(), otherProgram);
			if (toAddr == null) {
				return null;
			}
			return otherProgram.getReferenceManager()
				.getReference(fromAddr, toAddr, ref.getOperandIndex());
		}
		Reference otherRef = otherProgram.getReferenceManager()
			.getPrimaryReferenceFrom(fromAddr, ref.getOperandIndex());
		if (otherRef != null && ref.getToAddress().hasSameAddressSpace(otherRef.getToAddress())) {
			return otherRef;
		}
		return null;
	}

	/**
	 * 
	 * @param p2ToP1Translator
	 * @param p2Ref
	 * @return
	 */
	public static Reference getReference(AddressTranslator p2ToP1Translator, Reference p2Ref) {
		Program program = p2ToP1Translator.getDestinationProgram();
		Address fromAddr1 = p2ToP1Translator.getAddress(p2Ref.getFromAddress());
		if (fromAddr1 == null) {
			return null;
		}
		if (p2Ref.isMemoryReference()) {
			Address toAddr1 = p2ToP1Translator.getAddress(p2Ref.getToAddress());
			if (toAddr1 == null) {
				return null;
			}
			return program.getReferenceManager()
				.getReference(fromAddr1, toAddr1, p2Ref.getOperandIndex());
		}
		Reference p1Ref = program.getReferenceManager()
			.getPrimaryReferenceFrom(fromAddr1, p2Ref.getOperandIndex());
		if (p1Ref != null && p1Ref.getToAddress().hasSameAddressSpace(p2Ref.getToAddress())) {
			return p1Ref;
		}
		return null;
	}

	/**
	 * Create equivalent external location in otherProgram.
	 * @param program program containing extLoc
	 * @param extLoc existing external location to be copied
	 * @param otherProgram target program
	 * @return new external location
	 * @throws InvalidInputException
	 */
	public static ExternalLocation createExtLocation(Program program, ExternalLocation extLoc,
			Program otherProgram) throws InvalidInputException, DuplicateNameException {

		Address addr = extLoc.getAddress();
		Address otherAddr = null;
		if (addr != null) {
			otherAddr = getCompatibleAddress(program, addr, otherProgram);
		}
		// FIXME Should this be passing the Namespace?
		return otherProgram.getExternalManager()
			.addExtLocation(extLoc.getLibraryName(), extLoc.getLabel(), otherAddr,
				extLoc.getSource());
	}

	/**
	 * Given a reference for a specified program, create a comparable reference in the 
	 * specified otherProgram if possible. An open transaction on otherProgram must exist.
	 * @param program program which contains the specified reference instance
	 * @param ref reference to be added
	 * @param otherProgram other program
	 * @return new reference for otherProgram or null if unable to create reference.
	 */
	public static Reference createReference(final Program program, final Reference ref,
			final Program otherProgram) {

		ReferenceManager otherRefMgr = otherProgram.getReferenceManager();

		if (ref.isExternalReference()) {
			Address extAddr = ref.getToAddress();
			Symbol s = program.getSymbolTable().getPrimarySymbol(extAddr);
			if (s == null || !s.isExternal()) {
				return null;
			}
			try {
				// Create external location if not found
				ExternalLocation extLoc = program.getExternalManager().getExternalLocation(s);
				Symbol otherExtSym = getSymbol(s, otherProgram);
				ExternalLocation otherExtLoc;
				if (otherExtSym == null) {
					otherExtLoc = createExtLocation(program, extLoc, otherProgram);
				}
				else {
					otherExtLoc =
						otherProgram.getExternalManager().getExternalLocation(otherExtSym);
				}
				return otherRefMgr.addExternalReference(ref.getFromAddress(), ref.getOperandIndex(),
					otherExtLoc, ref.getSource(), ref.getReferenceType());
			}
			catch (DuplicateNameException e) {
				return null;
			}
			catch (InvalidInputException e) {
				throw new AssertException(e);
			}
		}

		Address otherFromAddress =
			getCompatibleAddress(program, ref.getFromAddress(), otherProgram);
		if (otherFromAddress == null) {
			return null;
		}
		Address otherToAddress = getCompatibleAddress(program, ref.getToAddress(), otherProgram);
		if (otherToAddress == null && !ref.isStackReference()) {
			return null;
		}

		Reference newRef;
		if (ref.isOffsetReference()) {
			newRef = otherRefMgr.addOffsetMemReference(otherFromAddress, otherToAddress,
				((OffsetReference) ref).getOffset(), ref.getReferenceType(), ref.getSource(),
				ref.getOperandIndex());
		}
		else if (ref.isShiftedReference()) {
			newRef = otherRefMgr.addShiftedMemReference(otherFromAddress, otherToAddress,
				((ShiftedReference) ref).getShift(), ref.getReferenceType(), ref.getSource(),
				ref.getOperandIndex());
		}
		else if (ref.isStackReference()) {
			StackReference stackRef = (StackReference) ref;
			if (otherProgram.getFunctionManager().isInFunction(otherFromAddress)) {
				return otherRefMgr.addStackReference(otherFromAddress, ref.getOperandIndex(),
					stackRef.getStackOffset(), ref.getReferenceType(), ref.getSource());
			}
			return null;
		}
		else if (ref.isMemoryReference() || ref.isRegisterReference()) {
			newRef = otherRefMgr.addMemoryReference(otherFromAddress, otherToAddress,
				ref.getReferenceType(), ref.getSource(), ref.getOperandIndex());
		}
		else {
			return null;
		}

		long symId = ref.getSymbolID();
		if (symId > 0) {
			Symbol s = program.getSymbolTable().getSymbol(symId);
			if (s != null) {
				s = getSymbol(s, otherProgram);
				if (s != null) {
					otherRefMgr.setAssociation(s, ref);
					newRef = otherRefMgr.getReference(newRef.getFromAddress(),
						newRef.getToAddress(), newRef.getOperandIndex());
				}
			}
		}
		if (ref.isPrimary() != newRef.isPrimary()) {
			otherRefMgr.setPrimary(newRef, ref.isPrimary());
		}
		return newRef;
	}

	/**
	 * Given a variable for a specified program, get the corresponding variable from the 
	 * specified otherProgram.
	 * @param program program which contains the specified variable instance
	 * @param var variable to look for
	 * @param otherProgram other program
	 * @return corresponding variable for otherProgram or null if no such variable exists.
	 */
	public static Variable getVariable(Program program, Variable var, Program otherProgram) {
		Symbol s = getSymbol(var.getSymbol(), otherProgram);
		return s != null ? (Variable) s.getObject() : null;
	}

	/**
	 * Given a variable, get the corresponding variable from the 
	 * specified otherFunction.
	 * @param var variable to look for
	 * @param otherFunction other function
	 * @return corresponding variable for otherFunction or null if no such variable exists.
	 */
	public static Variable getVariable(Variable var, Function otherFunction) {
		Symbol s = getVariableSymbol(var.getSymbol(), otherFunction);
		return s != null ? (Variable) s.getObject() : null;
	}

	/**
	 * Given a variable for a specified program, create a comparable variable in the 
	 * specified otherProgram if possible. An open transaction on otherProgram must exist.
	 * @param program program which contains the specified variable instance
	 * @param var variable to be added from program to otherProgram.
	 * @param otherProgram other program
	 * @return new variable for otherProgram or null if unable to create variable.
	 * @throws DuplicateNameException if another variable already exists with 
	 * the same name as var in the resulting function.
	 * @throws InvalidInputException if data type is not a fixed length or variable name is invalid, etc.
	 * @throws VariableSizeException if data type size is too large based upon storage constraints.
	 */
	public static Variable createVariable(Program program, Variable var, Program otherProgram)
			throws DuplicateNameException, InvalidInputException {

		Symbol parent = var.getSymbol().getParentSymbol();
		SourceType source = var.getSource();
		parent = getSymbol(parent, otherProgram);
		if (parent == null) {
			return null;
		}

// TODO: Method does not protect against duplicate variable (i.e., same offset, same first-use)

// TODO: Is it safe to use variable storage from one program into another?

		Namespace namespace = (Namespace) parent.getObject();
		if (namespace instanceof Function) {
			Function func = (Function) namespace;
			if (var instanceof Parameter) {
				return func.insertParameter(((Parameter) var).getOrdinal(), var, source);
			}
			return func.addLocalVariable(var, source);
		}

// TODO: Add GLOBAL or namespace variable support here

		return null;
	}

	/** Creates an address set that contains the entire code units within the
	 *  program's listing that are part of the address set that is passed in.
	 * <br>Note: This method will not remove any addresses from the address set even
	 * if they are not part of code units in the program's listing.
	 * @param addrSet The original address set that may contain portions of
	 * code units.
	 * @param program the program which has the code units.
	 * @return the address set that contains addresses for whole code units.
	 */
	public static AddressSet getCodeUnitSet(AddressSetView addrSet, Program program) {
		Listing listing = program.getListing();
		AddressSet addrs = new AddressSet(addrSet);
		AddressRangeIterator iter = addrSet.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			Address rangeMin = range.getMinAddress();
			Address rangeMax = range.getMaxAddress();
			CodeUnit minCu = listing.getCodeUnitContaining(rangeMin);
			if (minCu != null) {
				Address minCuMinAddr = minCu.getMinAddress();
				if (minCuMinAddr.compareTo(rangeMin) != 0) {
					addrs.addRange(minCuMinAddr, minCu.getMaxAddress());
				}
			}
			CodeUnit maxCu = listing.getCodeUnitContaining(rangeMax);
			if (maxCu != null) {
				Address maxCuMaxAddr = maxCu.getMaxAddress();
				if (maxCuMaxAddr.compareTo(rangeMax) != 0) {
					addrs.addRange(maxCu.getMinAddress(), maxCuMaxAddr);
				}
			}
		}
		return addrs;
	}

	/**
	 * Returns the signed hex string representing the int value. 
	 * Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
	 * Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
	 * @param value the value
	 * @return the signed hex string
	 */
	public static String toSignedHexString(int value) {
		return (value >= 0 ? "0x" + Integer.toHexString(value)
				: "-0x" + Integer.toHexString(-value));
	}

	/**
	 * Returns the signed hex string representing the long value. 
	 * Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
	 * Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
	 * @param value the value
	 * @return the signed hex string
	 */
	public static String toSignedHexString(long value) {
		return (value >= 0 ? "0x" + Long.toHexString(value) : "-0x" + Long.toHexString(-value));
	}

	/**
	 * Returns the string representation of the specified reference's "to" address.
	 * @param program the program containing the reference
	 * @param ref the reference
	 * @return the "to" address for the reference as a meaningful address for the user.
	 */
	public static String getUserToAddressString(Program program, Reference ref) {

		Address toAddr = ref.getToAddress();
		if (ref.isExternalReference()) {
			ExternalLocation extLoc = ((ExternalReference) ref).getExternalLocation();
			Address extAddr = extLoc.getAddress();
			String extLabel = extLoc.getLabel();
			return extLoc.getLibraryName() + "::" + (extLabel != null ? extLabel : "") +
				(extAddr != null ? (" (" + extAddr + ")") : "");
		}

		if (ref.isStackReference()) {
			int offset = ((StackReference) ref).getStackOffset();
			return "Stack[" + toSignedHexString(offset) + "]";
		}
		else if (ref.isOffsetReference()) {
			OffsetReference oref = (OffsetReference) ref;
			return toAddr.toString() + " " + "base:" +
				DiffUtility.getUserToAddressString(program, oref.getBaseAddress()) + " " +
				"offset:" + DiffUtility.toSignedHexString(oref.getOffset());

		}
		else if (ref.isShiftedReference()) {
			ShiftedReference sref = (ShiftedReference) ref;
			return toAddr.toString() + " " + "value:" + sref.getValue() + " " + "<<" +
				sref.getShift();
		}

		Register reg = program.getRegister(toAddr);
		if (reg != null) {
			return "register: " + reg.getName();
		}

		return toAddr.toString();

	}

	/**
	 * Returns a string representation of the specified address.
	 * @param program the program containing the address
	 * @param address the address
	 * @return the address as a meaningful string for the user.
	 */
	public static String getUserToAddressString(Program program, Address address) {
		if (address == null) {
			return ""; // Show nothing if no To Address.
		}
		if (address.isVariableAddress()) {
			// This should not occur with references
//			address = program.getVariableStorageManager().getStorageAddress(address);
//			if (address == null) {
//				return "Unknown";
//			}
		}
		if (address.isRegisterAddress()) {
			Register reg = program.getRegister(address);
			if (reg != null) {
				return "register:" + reg.getName();
			}
		}
		else if (address.isStackAddress()) {
			return "stack:" + toSignedHexString(address.getOffset());
		}
		return address.toString();
	}

	/**
	 * Returns the string representation of the specified reference's "to" symbol.
	 * @param program the program containing the reference
	 * @param ref the reference
	 * @return the "to" symbol for the reference as a meaningful string for the user. 
	 * The empty string, "", is returned if the reference isn't to a symbol. 
	 */
	public static String getUserToSymbolString(Program program, Reference ref) {

		if (ref.isExternalReference()) {
			ExternalLocation extLoc = ((ExternalReference) ref).getExternalLocation();
			return extLoc.getLibraryName() + "::" + extLoc.getLabel();
		}
		long id = ref.getSymbolID();
		Symbol s = (id >= 0) ? program.getSymbolTable().getSymbol(id) : null;
		return (s != null) ? s.getName() : "";
	}

	public static ProgramLocation getCompatibleProgramLocation(Program program,
			ProgramLocation location, Program otherProgram) {
		Address address = getCompatibleAddress(program, location.addr, otherProgram);
		Address byteAddress =
			getCompatibleAddress(program, location.getByteAddress(), otherProgram);
		Address refAddress = getCompatibleAddress(program, location.refAddr, otherProgram);

		if (address != null) {
			if (byteAddress == null) {
				byteAddress = address; // Make sure the byte address isn't null.
			}
			ProgramLocation otherLocation = new ProgramLocation(otherProgram, address, byteAddress,
				location.getComponentPath(), refAddress, 0, 0, 0);
			return otherLocation;
		}
		return null;
	}

}
