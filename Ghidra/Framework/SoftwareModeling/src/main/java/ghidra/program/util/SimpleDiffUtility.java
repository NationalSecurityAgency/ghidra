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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class SimpleDiffUtility {

	/**
	 * Convert a variable storage object from the specified program to a comparable variable storage
	 * object in the specified otherProgram.  Certain variable storage (UNIQUE/HASH-based) will
	 * always produce a null return object.
	 * @param program program which contains the specified address instance
	 * @param storage variable storage in program
	 * @param otherProgram other program
	 * @return storage for otherProgram or null if storage can not be mapped to other program
	 */
	public static VariableStorage getCompatibleVariableStorage(Program program,
			VariableStorage storage, Program otherProgram) {
		if (storage == null || storage.size() == 0 || storage.isHashStorage()) {
			return storage;
		}
		Varnode[] varnodes = storage.getVarnodes();
		for (int i = 0; i < varnodes.length; i++) {
			varnodes[i] = getCompatibleVarnode(program, varnodes[i], otherProgram);
			if (varnodes[i] == null) {
				return null;
			}
		}
		try {
			return new VariableStorage(otherProgram, varnodes);
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e); // unexpected
		}
	}

	/**
	 * Convert a varnode from the specified program to a comparable varnode in the
	 * specified otherProgram.  Certain varnode addresses spaces (UNIQUE, HASH) will
	 * always produce a null return varnode.
	 * @param program program which contains the specified address instance
	 * @param varnode varnode in program
	 * @param otherProgram other program
	 * @return varnode for otherProgram or null if varnode can not be mapped to other program
	 */
	public static Varnode getCompatibleVarnode(Program program, Varnode varnode,
			Program otherProgram) {
		if (varnode == null || varnode.isConstant()) {
			return varnode;
		}
		Address addr = varnode.getAddress();
		if (addr.isRegisterAddress()) {
			if (program.getLanguageID().equals(otherProgram.getLanguageID())) {
				return varnode;
			}
			// TODO: Handle improperly aligned offcut register varnodes.
			Register reg = program.getRegister(addr, varnode.getSize());
			if (reg != null) {
				Register otherReg = otherProgram.getRegister(reg.getName());
				if (otherReg != null && reg.getMinimumByteSize() == otherReg.getMinimumByteSize()) {
					long delta = addr.subtract(reg.getAddress());
					if (delta != 0) {
						return new Varnode(otherReg.getAddress().add(delta), varnode.getSize());
					}
					return new Varnode(otherReg.getAddress(), varnode.getSize());
				}
			}
			return null;
		}
		else if (addr.isMemoryAddress() || addr.isStackAddress()) {
			Address otherAddr = getCompatibleAddress(program, addr, otherProgram);
			if (otherAddr != null) {
				return new Varnode(otherAddr, varnode.getSize());
			}
		}
		return null;
	}

	/*
	 * If the specified instruction is contained within a delay slot the minimum address
	 * of the primary instruction will be returned.  If not in a delay slot, the specified
	 * instructions minimum address is returned.
	 * @param instr
	 * @return minimum address of primary instruction
	 */
	public static Address getStartOfDelaySlots(Instruction instr) {
		Listing listing = instr.getProgram().getListing();
		Instruction prevInstr = instr;
		Address minAddr = prevInstr.getMinAddress();
		try {
			while (prevInstr != null && prevInstr.isInDelaySlot()) {
				minAddr = prevInstr.getMinAddress();
				prevInstr = listing.getInstructionContaining(minAddr.subtractNoWrap(1));
			}
			if (prevInstr != null) {
				minAddr = prevInstr.getMinAddress();
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}
		return minAddr;
	}

	/**
	 * If the specified instruction is contained within a delay slot, or has delay slots,
	 * the maximum address of the last delay slot instruction will be returned.
	 * If a normal instruction is specified the instructions maximum address is returned.
	 * @param instr
	 * @return maximum address of instruction or its last delay slot
	 */
	public static Address getEndOfDelaySlots(Instruction instr) {
		Listing listing = instr.getProgram().getListing();
		Address maxAddr = instr.getMaxAddress();
		try {
			Instruction nextInstr = listing.getInstructionAt(maxAddr.addNoWrap(1));
			while (nextInstr != null && nextInstr.isInDelaySlot()) {
				maxAddr = nextInstr.getMaxAddress();
				nextInstr = listing.getInstructionAt(maxAddr.addNoWrap(1));
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}
		return maxAddr;
	}

	/**
	 * Expand a specified address set to include complete delay slotted instructions
	 * which may be included at the start or end of each range within the specified
	 * address set.
	 * @param program program
	 * @param originalSet original address set
	 * @return expanded address set
	 */
	public static AddressSetView expandAddressSetToIncludeFullDelaySlots(Program program,
			AddressSetView originalSet) {
		Listing listing = program.getListing();
		AddressSet expandedSet = null;
		for (AddressRange originRange : originalSet.getAddressRanges()) {

			Instruction instr = listing.getInstructionAt(originRange.getMinAddress());
			if (instr != null && instr.isInDelaySlot()) {
				// expand range up
				Address newMinAddr = getStartOfDelaySlots(instr);
				if (!newMinAddr.equals(originRange.getMinAddress())) {
					if (expandedSet == null) {
						expandedSet = new AddressSet(originalSet);
					}
					expandedSet.addRange(newMinAddr, instr.getMaxAddress());
				}
			}

			instr = listing.getInstructionContaining(originRange.getMaxAddress());
			if (instr != null && (instr.isInDelaySlot() || instr.getDelaySlotDepth() != 0)) {
				// expand range down
				Address newMaxAddr = getEndOfDelaySlots(instr);
				if (!newMaxAddr.equals(originRange.getMaxAddress())) {
					if (expandedSet == null) {
						expandedSet = new AddressSet(originalSet);
					}
					expandedSet.addRange(instr.getMinAddress(), newMaxAddr);
				}
			}
		}
		return expandedSet != null ? expandedSet : originalSet;
	}

	/**
	 * Convert an address from the specified program to a comparable address in the
	 * specified otherProgram.  
	 * <br>
	 * For external locations the match-up is very fuzzy and
	 * will use correlated references.  If an exact match is required for an external location
	 * the {@link #getMatchingExternalLocation(Program, ExternalLocation, Program, boolean)} or 
	 * {@link #getMatchingExternalSymbol(Program, Symbol, Program, boolean, Set)} should be used 
	 * directly.
	 * 
	 * @param program program which contains the specified address instance
	 * @param addr address in program
	 * @param otherProgram other program
	 * @return address for otherProgram or null if no such address exists.
	 */
	public static Address getCompatibleAddress(Program program, Address addr,
			Program otherProgram) {
		if (addr == null) {
			return null;
		}
		if (addr.isMemoryAddress()) {
			return translateMemoryAddress(addr, otherProgram, true);
		}
		else if (addr.isVariableAddress()) {
// TODO: We should not attempt to correlate variables by their variable address
			throw new IllegalArgumentException(
				"correlation of variables by their variable address not allowed");
//          Address storageAddr = program.getVariableStorageManager().getStorageAddress(addr);
//          if (storageAddr == null) {
//              return null;
//          }
//          Address otherStorageAddr = getCompatibleAddress(program, storageAddr, otherProgram);
//          if (otherStorageAddr == null) {
//              return null;
//          }
//
//          Namespace namespace = program.getVariableStorageManager().getNamespace(addr);
//          Namespace otherNamespace = getNamespace(program, namespace, otherProgram);
//          if (otherNamespace == null) {
//              return null;
//          }
//          return otherProgram.getVariableStorageManager().findVariableAddress(otherNamespace.getID(), otherStorageAddr);
		}
		else if (addr.isStackAddress()) {
			return otherProgram.getAddressFactory().getStackSpace().getAddress(addr.getOffset());
		}
		else if (addr.isRegisterAddress()) {
			if (program.getLanguage()
					.getLanguageID()
					.equals(otherProgram.getLanguage().getLanguageID())) {
				return addr;
			}
			// TODO: should we handle small varnodes within big endian registers
			Register reg = program.getRegister(addr);
			if (reg != null) {
				Register otherReg = otherProgram.getRegister(reg.getName());
				if (otherReg != null && reg.getMinimumByteSize() == otherReg.getMinimumByteSize()) {
					long delta = addr.subtract(reg.getAddress());
					if (delta != 0) {
						return otherReg.getAddress().add(delta);
					}
					return otherReg.getAddress();
				}
			}
			return null;
		}
		else if (addr.isExternalAddress()) {
			Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
			if (s != null && s.isExternal()) {
				s = getMatchingExternalSymbol(program, s, otherProgram, true, null);
				if (s != null) {
					return s.getAddress();
				}
			}
			return null;
		}
		else if (addr.getAddressSpace().getType() == AddressSpace.TYPE_NONE ||
			addr.getAddressSpace().getType() == AddressSpace.TYPE_UNKNOWN) {
// TODO: Not sure if this is correct ??
			return addr;
		}
		throw new IllegalArgumentException("Unsupported address type");
	}

	/**
	 * Convert an address from the specified program to a comparable address in the
	 * specified otherProgram.
	 * @param addr address in program
	 * @param otherProgram other program
	 * @param exactMatchOnly if false and addr is an overlay address, a closest match will be returned
	 * if possible
	 * @return address for otherProgram or null if no such address exists.
	 */
	protected static Address translateMemoryAddress(Address addr, Program otherProgram,
			boolean exactMatchOnly) {
		if (!addr.isMemoryAddress()) {
			return null;
		}
		AddressSpace addrSpace = addr.getAddressSpace();
		AddressSpace otherSpace = getCompatibleAddressSpace(addrSpace, otherProgram);
		if (otherSpace != null) {
			try {
				return otherSpace.getAddressInThisSpaceOnly(addr.getOffset());
			}
			catch (AddressOutOfBoundsException e) {
				return null;
			}
		}
		return null;
	}

	public static AddressSpace getCompatibleAddressSpace(AddressSpace addrSpace,
			Program otherProgram) {
		AddressSpace otherSpace =
			otherProgram.getAddressFactory().getAddressSpace(addrSpace.getName());
		if (otherSpace != null && otherSpace.getType() == addrSpace.getType() &&
			otherSpace.isOverlaySpace() == addrSpace.isOverlaySpace()) {
			int id = addrSpace.isOverlaySpace() ? ((OverlayAddressSpace) addrSpace).getBaseSpaceID()
					: addrSpace.getSpaceID();
			int otherid =
				otherSpace.isOverlaySpace() ? ((OverlayAddressSpace) otherSpace).getBaseSpaceID()
						: otherSpace.getSpaceID();
			// NOTE: This only works for the same language
			if (id == otherid) {
				return otherSpace;
			}
		}
		return null;
	}

	/**
	 * Given a symbol for a specified program, get the corresponding symbol from the
	 * specified otherProgram.
	 * <br>
	 * In the case of external locations this performs an exact match based upon symbol name, 
	 * namespace and symbol type.
	 * 
	 * @param symbol symbol to look for
	 * @param otherProgram other program
	 * @return corresponding symbol for otherProgram or null if no such symbol exists.
	 */
	public static Symbol getSymbol(Symbol symbol, Program otherProgram) {
		if (symbol == null) {
			return null;
		}

		SymbolType symbolType = symbol.getSymbolType();

		if (symbolType == SymbolType.GLOBAL) {
			return otherProgram.getGlobalNamespace().getSymbol();
		}

		String name = symbol.getName();
		Symbol otherParent = getSymbol(symbol.getParentSymbol(), otherProgram);
		Namespace otherNamespace = otherParent == null ? null : (Namespace) otherParent.getObject();
		if (otherNamespace == null) {
			return null;
		}

		if (symbolType == SymbolType.LIBRARY) {
			return otherProgram.getSymbolTable().getLibrarySymbol(name);
		}
		if (symbolType == SymbolType.CLASS) {
			return otherProgram.getSymbolTable().getClassSymbol(name, otherNamespace);
		}
		if (symbolType == SymbolType.NAMESPACE) {
			return otherProgram.getSymbolTable().getNamespaceSymbol(name, otherNamespace);
		}
		if (symbolType == SymbolType.PARAMETER || symbolType == SymbolType.LOCAL_VAR) {
			return getVariableSymbol(symbol, otherProgram, otherNamespace);
		}
		if (symbolType == SymbolType.FUNCTION) {
			return getOtherFunctionSymbol(symbol, otherProgram, otherNamespace);
		}
		if (symbolType == SymbolType.LABEL) {
			return getOtherCodeSymbol(symbol, otherProgram, otherNamespace);
		}
		// In case any new SymbolTypes get added
		throw new AssertException("Got unexpected SymbolType: " + symbolType);
	}

	private static Symbol getOtherCodeSymbol(Symbol symbol, Program otherProgram,
			Namespace namespace) {

		if (symbol.isExternal()) {
			return getOtherExternalLocationSymbol(symbol, otherProgram, namespace);
		}

		Address otherAddress =
			getCompatibleAddress(symbol.getProgram(), symbol.getAddress(), otherProgram);

		if (otherAddress == null) {
			return null;
		}

		Symbol otherSymbol =
			otherProgram.getSymbolTable().getSymbol(symbol.getName(), otherAddress, namespace);

		SymbolType otherType = otherSymbol == null ? null : otherSymbol.getSymbolType();

		if (otherType == symbol.getSymbolType()) {
			return otherSymbol;
		}

		return null;
	}

	private static Symbol getOtherFunctionSymbol(Symbol symbol, Program otherProgram,
			Namespace otherNamespace) {
		if (symbol.isExternal()) {
			return getOtherExternalLocationSymbol(symbol, otherProgram, otherNamespace);
		}

		Function func = (Function) symbol.getObject();
		Address entryPoint = func.getEntryPoint();
		Address otherEntry = getCompatibleAddress(symbol.getProgram(), entryPoint, otherProgram);
		if (otherEntry == null) {
			return null;
		}
		func = otherProgram.getFunctionManager().getFunctionAt(otherEntry);
		return func != null ? func.getSymbol() : null;
	}

	private static Symbol getOtherExternalLocationSymbol(Symbol symbol, Program otherProgram,
			Namespace otherNamespace) {

		ExternalLocation external = getExternalLocation(symbol);

		// TODO: This match-up is exact based upon name and namespace and does not consider 
		// the original imported name or address, however these attributes must match. 

		// TODO: It is rather confusing to have two sets of methods for finding external
		// locations.  This should be simplified.  getOther... getMatchingExternal...

		SymbolTable otherSymbolTable = otherProgram.getSymbolTable();
		List<Symbol> otherSymbols = otherSymbolTable.getSymbols(symbol.getName(), otherNamespace);

		if (otherSymbols.size() == 1) {
			Symbol s = otherSymbols.get(0);
			return s.getSymbolType() == symbol.getSymbolType() ? s : null;
		}

		for (Symbol s : otherSymbols) {
			ExternalLocation otherExternalLocation = getExternalLocation(s);
			if (external.isEquivalent(otherExternalLocation)) {
				return s;
			}
		}
		return null;
	}

	private static ExternalLocation getExternalLocation(Symbol symbol) {
		if (symbol == null) {
			return null;
		}
		Program p = symbol.getProgram();
		return p.getExternalManager().getExternalLocation(symbol);
	}

	private static class ExternalReferenceCount implements Comparable<ExternalReferenceCount> {

		static final int ADDRESS_RANK = 3;
		static final int NAME_RANK = 2;
		static final int NAMESPACE_RANK = 1;
		static final int MANGLED_NAME_RANK = NAME_RANK + NAMESPACE_RANK;

		final ExternalLocation extLoc;
		final ExternalMatchType matchType;
		int refCount = 1;
		int rank;

		ExternalReferenceCount(ExternalLocation extLoc, ExternalMatchType matchType) {
			this.extLoc = extLoc;
			this.matchType = matchType;
		}

		ExternalLocation getExternalLocation() {
			return extLoc;
		}

		Symbol getSymbol() {
			return extLoc.getSymbol();
		}

		SymbolType getSymbolType() {
			return getSymbol().getSymbolType();
		}

		String getSymbolName() {
			return getSymbol().getName();
		}

		String getFullNamespaceName() {
			return getSymbol().getParentNamespace().getName(true);
		}

		@Override
		public int compareTo(ExternalReferenceCount other) {
			int diff = other.rank - rank;
			if (diff != 0) {
				return diff;
			}
			diff = other.refCount - refCount;
			if (diff != 0) {
				return diff;
			}
			// Sort functions before labels, SYmbolType IDs: CODE=0, FUNCTION=5
			diff = other.getSymbolType().getID() - getSymbolType().getID();
			if (diff != 0) {
				return diff;
			}
			return getSymbol().getName(true).compareTo(other.getSymbol().getName(true));
		}

		/**
		 * Generate relative rank when a non-default name match occurs.
		 * Method should not be invoked when either location symbol has a default source type.
		 * @param targetAddr
		 * @param targetNamespace
		 * @param targetName
		 * @param targetOrigImportedName
		 */
		void setRelativeRank(Address targetAddr, String targetNamespace, String targetName,
				String targetOrigImportedName) {
			rank = 0;

			if (matchType == ExternalMatchType.ADDRESS) {
				rank = ADDRESS_RANK;
				return;
			}

			if (targetAddr != null) {
				Address myAddr = extLoc.getAddress();
				if (myAddr != null && targetAddr.equals(myAddr)) {
					rank += ADDRESS_RANK; // address match
				}
				else if (myAddr != null) {
					// If memory addresses both specified and differ - reduce rank
					rank -= ADDRESS_RANK;
				}
			}

			if (matchType == ExternalMatchType.MANGLED_NAME) {
				rank += MANGLED_NAME_RANK;
				return;
			}

			if (matchType != ExternalMatchType.NAME) {
				return;
			}

			// Impose mangled name mismatch penalty
			String myOrigImportedName = extLoc.getOriginalImportedName();
			if (targetOrigImportedName != null && myOrigImportedName != null) {
				rank -= MANGLED_NAME_RANK;
				return;
			}

			// assume NAME match
			rank += NAME_RANK;

			if (targetNamespace != null && targetNamespace.equals(getFullNamespaceName())) {
				rank += NAMESPACE_RANK; // non-default namespace match improves name match
			}
		}

	}

	private enum ExternalMatchType {
		NONE, NAME, MANGLED_NAME, ADDRESS;
	}

	private static ExternalMatchType testExternalMatch(ExternalLocation extLoc1,
			ExternalLocation extLoc2) {
		ExternalMatchType matchType = testExternalNameMatch(extLoc1, extLoc2);
		if (matchType == ExternalMatchType.NONE) {
			return hasExternalAddressMatch(extLoc1, extLoc2) ? ExternalMatchType.ADDRESS
					: ExternalMatchType.NONE;
		}
		return matchType;
	}

	private static boolean hasExternalAddressMatch(ExternalLocation extLoc1,
			ExternalLocation extLoc2) {
		Address addr1 = extLoc1.getAddress();
		return addr1 != null && addr1.equals(extLoc2.getAddress());
	}

	private static ExternalMatchType testExternalNameMatch(ExternalLocation extLoc1,
			ExternalLocation extLoc2) {
		boolean isDefaul1 = extLoc1.getSymbol().getSource() == SourceType.DEFAULT;
		boolean isDefaul2 = extLoc2.getSymbol().getSource() == SourceType.DEFAULT;
		if (isDefaul1 || isDefaul2) {
			return ExternalMatchType.NONE;
		}
		if (!extLoc1.getLibraryName().equals(extLoc2.getLibraryName())) {
			return ExternalMatchType.NONE; // assume this prevails over Namespace
		}

		String name1 = extLoc1.getLabel();
		String name2 = extLoc2.getLabel();
		String origName1 = extLoc1.getOriginalImportedName();
		String origName2 = extLoc2.getOriginalImportedName();
		if (origName1 != null) {
			if (origName2 != null) {
				// assume mangled names if both known must match
				return origName1.equals(origName2) ? ExternalMatchType.MANGLED_NAME
						: ExternalMatchType.NONE;
			}
			// mangled name must be in root namespace of library
			if (extLoc2.getSymbol().getParentNamespace().isLibrary() && origName1.equals(name2)) {
				return ExternalMatchType.MANGLED_NAME;
			}
		}
		else if (origName2 != null && extLoc1.getSymbol().getParentNamespace().isLibrary() &&
			origName2.equals(name1)) {
			return ExternalMatchType.MANGLED_NAME;
		}
		return name1.equals(name2) ? ExternalMatchType.NAME : ExternalMatchType.NONE;
	}

	/**
	 * Given an external symbol for a specified program, get the corresponding symbol,
	 * which has the same name and path,  from the specified otherProgram.<br>
	 * Note: In The type of the returned symbol may be different than the type of the symbol
	 * (i.e., Function vs Label).
	 * @param program program which contains the specified symbol instance
	 * @param symbol symbol to look for
	 * @param otherProgram other program
	 * @param allowInferredMatch if true an inferred match may be performed using reference
	 * correlation (NOTE: reference correlation is only possible if the exact same binary
	 * is in use).  This option is ignored if the two programs do not have the same 
	 * original binary hash. 
	 * @param otherRestrictedSymbolIds an optional set of symbol ID's from the other program
	 * which will be treated as the exclusive set of candidate symbols to consider.
	 * @return corresponding external symbol for otherProgram or null if no such symbol exists.
	 */
	public static Symbol getMatchingExternalSymbol(Program program, Symbol symbol,
			Program otherProgram, boolean allowInferredMatch, Set<Long> otherRestrictedSymbolIds) {

		// TODO: It is rather confusing to have two sets of methods for finding external
		// locations.  This should be simplified.  getOther... getMatchingExternal...

		if (symbol == null) {
			return null;
		}
		SymbolType type = symbol.getSymbolType();
		if ((type != SymbolType.FUNCTION && type != SymbolType.LABEL) || !symbol.isExternal()) {
			return null;
		}

		if (allowInferredMatch) {
			// Inferred reference-based match only valid for the same program (i.e., multi-user merge)
			if (program.getUniqueProgramID() != otherProgram.getUniqueProgramID()) {
				allowInferredMatch = false;
			}
		}

		ExternalManager extMgr = program.getExternalManager();
		ExternalLocation extLoc = extMgr.getExternalLocation(symbol);

		String targetName = symbol.getSource() != SourceType.DEFAULT ? symbol.getName() : null;
		String targetOrigImportedName = extLoc.getOriginalImportedName();
		String targetNamespace = symbol.getParentNamespace().getName(true);
		if (targetNamespace.startsWith(Library.UNKNOWN)) {
			targetNamespace = null;
		}
		Address targetAddr = extLoc.getAddress();

		SymbolTable otherSymbMgr = otherProgram.getSymbolTable();
		ExternalManager otherExtMgr = otherProgram.getExternalManager();

		HashMap<Address, ExternalReferenceCount> matchesMap = new HashMap<>();

		// Search by name
		if (symbol.getSource() != SourceType.DEFAULT) {

			// TODO: Need to improve support for lookup based upon other fields
			// Need separate Symbol DB indexing of ExternalLocation fields (address,originalImportName)

			Symbol otherParent = getSymbol(symbol.getParentSymbol(), otherProgram);
			if (otherParent != null) {
				SymbolIterator symbols =
					otherProgram.getSymbolTable().getExternalSymbols(symbol.getName());
				for (Symbol otherSym : symbols) {
					ExternalLocation otherExtLoc = otherExtMgr.getExternalLocation(otherSym);
					if (otherExtLoc != null) {
						ExternalMatchType matchType = testExternalMatch(otherExtLoc, extLoc);
						if (matchType == ExternalMatchType.NONE) {
							continue;
						}
						ExternalReferenceCount refMatch =
							new ExternalReferenceCount(otherExtLoc, matchType);
						refMatch.setRelativeRank(targetAddr, targetNamespace, targetName,
							targetOrigImportedName);
						matchesMap.put(otherSym.getAddress(), refMatch);
					}
				}
			}
		}

		if (allowInferredMatch && matchesMap.isEmpty()) {
			// Process references
			ReferenceManager refMgr = program.getReferenceManager();
			ReferenceManager otherRefMgr = otherProgram.getReferenceManager();
			ReferenceIterator refIter = refMgr.getReferencesTo(symbol.getAddress());
			int totalMatchCnt = 0;
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				Reference otherRef = otherRefMgr.getPrimaryReferenceFrom(ref.getFromAddress(),
					ref.getOperandIndex());
				if (otherRef == null || !otherRef.isExternalReference()) {
					continue;
				}
				Address otherExtAddr = otherRef.getToAddress();
				ExternalReferenceCount refMatch = matchesMap.get(otherExtAddr);
				if (refMatch == null) {
					Symbol otherSym = otherSymbMgr.getPrimarySymbol(otherExtAddr);
					if (otherRestrictedSymbolIds != null &&
						!otherRestrictedSymbolIds.contains(otherSym.getID())) {
						continue;
					}
					ExternalLocation otherExtLoc = otherExtMgr.getExternalLocation(otherSym);
					ExternalMatchType matchType = testExternalMatch(otherExtLoc, extLoc);
					refMatch = new ExternalReferenceCount(otherExtLoc, matchType);
					if (matchType != ExternalMatchType.NONE) {
						refMatch.setRelativeRank(targetAddr, targetNamespace, targetName,
							targetOrigImportedName);
					}
					matchesMap.put(otherExtAddr, refMatch);
				}
				else {
					++refMatch.refCount;
				}
				if (++totalMatchCnt == 20) {
					break;
				}
			}

			// Process thunk-references (include all)
			if (extLoc.isFunction()) {
				Address[] thunkAddrs = extLoc.getFunction().getFunctionThunkAddresses();
				if (thunkAddrs != null) {
					for (Address thunkAddr : thunkAddrs) {
						Symbol otherThunkSym = otherSymbMgr.getPrimarySymbol(thunkAddr);
						if (otherThunkSym == null ||
							otherThunkSym.getSymbolType() != SymbolType.FUNCTION) {
							continue;
						}
						Function otherFunc = (Function) otherThunkSym.getObject();
						Function otherThunkedFunc = otherFunc.getThunkedFunction(false);
						if (otherThunkedFunc == null || !otherThunkedFunc.isExternal()) {
							continue;
						}
						ExternalReferenceCount refMatch =
							matchesMap.get(otherThunkedFunc.getEntryPoint());
						if (refMatch == null) {
							if (otherRestrictedSymbolIds != null &&
								!otherRestrictedSymbolIds.contains(otherThunkedFunc.getID())) {
								continue;
							}
							ExternalLocation otherExtLoc =
								otherExtMgr.getExternalLocation(otherThunkedFunc.getSymbol());
							ExternalMatchType matchType = testExternalMatch(otherExtLoc, extLoc);
							refMatch = new ExternalReferenceCount(otherExtLoc, matchType);
							if (matchType != ExternalMatchType.NONE) {
								refMatch.setRelativeRank(targetAddr, targetNamespace, targetName,
									targetOrigImportedName);
							}
							matchesMap.put(otherThunkedFunc.getEntryPoint(), refMatch);
						}
						else {
							++refMatch.refCount;
						}
					}
				}
			}
		}

		if (matchesMap.isEmpty()) {
			// Brute force search for match candidates using address/name
			// This will occur anytime an external add occurs on program and not otherProgram
			for (Symbol otherSym : otherSymbMgr.getExternalSymbols()) {
				if (otherRestrictedSymbolIds != null &&
					!otherRestrictedSymbolIds.contains(otherSym.getID())) {
					continue;
				}
				ExternalLocation otherExtLoc = otherExtMgr.getExternalLocation(otherSym);
				if (otherExtLoc != null) {
					ExternalMatchType matchType = testExternalMatch(otherExtLoc, extLoc);
					if (matchType == ExternalMatchType.NONE) {
						continue;
					}
					ExternalReferenceCount refMatch =
						new ExternalReferenceCount(otherExtLoc, matchType);
					refMatch.setRelativeRank(targetAddr, targetNamespace, targetName,
						targetOrigImportedName);
					matchesMap.put(otherSym.getAddress(), refMatch);
				}
			}
			if (matchesMap.isEmpty()) {
				return null;
			}
		}

		ExternalReferenceCount[] matches =
			matchesMap.values().toArray(new ExternalReferenceCount[matchesMap.size()]);
		if (matches.length == 1) {
			// If only one match candidate - rank of 0 is OK
			return matches[0].rank >= 0 ? matches[0].getSymbol() : null;
		}

		// If multiple matches, rank > 0 required (i.e., must match on name and/or addr)
		Arrays.sort(matches);
		return matches[0].rank > 0 ? matches[0].getSymbol() : null;
	}

	/**
	 * Given an external location for a specified program, get the corresponding external location,
	 * which has the same name and path,  from the specified otherProgram.<br>
	 * Note: The type of the returned external location may be different than the type of the
	 * original external location.
	 * @param program program which contains the specified external location instance
	 * @param externalLocation external location to look for
	 * @param otherProgram other program
	 * @param allowInferredMatch if true an inferred match may be performed using reference
	 * correlation.  NOTE: reference correlation is only possible if the exact same binary
	 * is in use.  This option is ignored if the two programs do not have the same 
	 * original binary hash and reference correlation will not be performed.
	 * @return corresponding external location for otherProgram or null if no such external location exists.
	 */
	public static ExternalLocation getMatchingExternalLocation(Program program,
			ExternalLocation externalLocation, Program otherProgram, boolean allowInferredMatch) {
		if (externalLocation == null) {
			return null;
		}
		Symbol symbol = externalLocation.getSymbol();
		if (symbol == null) {
			return null;
		}
		Symbol matchingExternalSymbol =
			getMatchingExternalSymbol(program, symbol, otherProgram, allowInferredMatch, null);
		if (matchingExternalSymbol == null) {
			return null;
		}
		ExternalManager otherExternalManager = otherProgram.getExternalManager();
		return otherExternalManager.getExternalLocation(matchingExternalSymbol);
	}

	/**
	 * Find the variable symbol in otherProgram which corresponds to the specified varSym.
	 * @param symbol variable symbol
	 * @param otherProgram other program
	 * @return the variable symbol or null
	 */
	public static Symbol getVariableSymbol(Symbol symbol, Program otherProgram) {
		Symbol otherParent = getSymbol(symbol.getParentSymbol(), otherProgram);
		Namespace namespace = otherParent == null ? null : (Namespace) otherParent.getObject();
		return getVariableSymbol(symbol, otherProgram, namespace);
	}

	protected static Symbol getVariableSymbol(Symbol varSym, Program otherProgram,
			Namespace otherNamespace) {
		if (!(otherNamespace instanceof Function)) {
			return null;
		}

		Program program = varSym.getProgram();
		SymbolTable otherSymTable = otherProgram.getSymbolTable();
		Variable var = (Variable) varSym.getObject();

		VariableStorage otherStorage =
			getCompatibleVariableStorage(program, var.getVariableStorage(), otherProgram);
		if (otherStorage == null || otherStorage.isBadStorage()) {
			return null;
		}
		Variable minVar =
			getOverlappingVariable(otherSymTable, var, otherStorage, otherNamespace.getSymbol());
		if (minVar != null) {
			return minVar.getSymbol();
		}
		return null;
	}

	/**
	 * Find the variable symbol in otherFunction which corresponds to the specified varSym.
	 * @param varSym variable symbol
	 * @param otherFunction other function
	 * @return the variable symbol or null
	 */
	protected static Symbol getVariableSymbol(Symbol varSym, Function otherFunction) {
		Program program = varSym.getProgram();
		Program otherProgram = otherFunction.getProgram();
		SymbolTable otherSymTable = otherProgram.getSymbolTable();
		Variable var = (Variable) varSym.getObject();
		Symbol otherFuncSym = otherFunction.getSymbol();
		if (otherFuncSym == null || otherFuncSym.getSymbolType() != SymbolType.FUNCTION) {
			return null;
		}
		VariableStorage storage =
			getCompatibleVariableStorage(program, var.getVariableStorage(), otherProgram);
		if (storage == null || storage.isBadStorage()) {
			return null;
		}
		Variable minVar = getOverlappingVariable(otherSymTable, var, storage, otherFuncSym);
		if (minVar != null) {
			return minVar.getSymbol();
		}
		return null;
	}

	/**
	 * Find overlapping variable which meets the following conditions
	 * 1. First use offset matches
	 * 2. Ordinal matches (for parameters only)
	 * 3. Minimum or maximum address matches
	 * @param otherSymTable other symbol table
	 * @param var variable
	 * @param otherStorage other variable storage
	 * @param otherFunctionSymbol other function symbol
	 * @return the overlapping variable or null
	 */
	protected static Variable getOverlappingVariable(SymbolTable otherSymTable, Variable var,
			VariableStorage otherStorage, Symbol otherFunctionSymbol) {
		SymbolType symbolType = var.getSymbol().getSymbolType();
		int ordinal = -1;
		if (var instanceof Parameter) {
			ordinal = ((Parameter) var).getOrdinal();
		}
		int firstUseOffset = var.getFirstUseOffset();

		SymbolIterator symbolIter = otherSymTable.getSymbols(otherFunctionSymbol.getID());
		while (symbolIter.hasNext()) {
			Symbol s = symbolIter.next();
			if (s.getSymbolType() != symbolType) {
				continue;
			}
			Variable v = (Variable) s.getObject();
			if (v instanceof Parameter && ordinal != ((Parameter) v).getOrdinal()) {
				continue;
			}
			if (firstUseOffset != v.getFirstUseOffset()) {
				continue;
			}
			if (v.getVariableStorage().equals(otherStorage)) {
				return v;
			}
		}
		return null;
	}

}
