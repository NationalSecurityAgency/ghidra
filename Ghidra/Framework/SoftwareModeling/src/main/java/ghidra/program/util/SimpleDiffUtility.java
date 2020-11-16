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
			if (program.getLanguage().getLanguageID().equals(
				otherProgram.getLanguage().getLanguageID())) {
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
				s = getSymbol(s, otherProgram);
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
			if (addrSpace.isOverlaySpace()) {
				long offset = addr.getOffset();
				if (offset < otherSpace.getMinAddress().getOffset()) {
					return exactMatchOnly ? null : otherSpace.getMinAddress();
				}
				else if (offset > otherSpace.getMaxAddress().getOffset()) {
					return exactMatchOnly ? null : otherSpace.getMaxAddress();
				}
				return otherSpace.getAddress(offset);
			}
			return otherSpace.getAddress(addr.getOffset());
		}
		return null;
	}

	public static AddressSpace getCompatibleAddressSpace(AddressSpace addrSpace,
			Program otherProgram) {
		AddressSpace otherSpace =
			otherProgram.getAddressFactory().getAddressSpace(addrSpace.getName());
		if (otherSpace != null && otherSpace.getType() == addrSpace.getType()) {
			int id = addrSpace.isOverlaySpace() ? ((OverlayAddressSpace) addrSpace).getBaseSpaceID()
					: addrSpace.getSpaceID();
			int otherid =
				otherSpace.isOverlaySpace() ? ((OverlayAddressSpace) otherSpace).getBaseSpaceID()
						: otherSpace.getSpaceID();
			if (id == otherid) {
				if (otherSpace.isOverlaySpace()) {
					long addrOffset = addrSpace.getMinAddress().getOffset();
					long otherOffset = otherSpace.getMinAddress().getOffset();
					if (addrOffset != otherOffset) {
						return null; // Overlays didn't begin at same address.
					}
				}
				return otherSpace;
			}
		}
		return null;
	}

	/**
	 * Given a symbol for a specified program, get the corresponding symbol from the
	 * specified otherProgram.
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

		final ExternalLocation extLoc;
		int refCount = 1;
		int rank;

		ExternalReferenceCount(ExternalLocation extLoc) {
			this.extLoc = extLoc;
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

		public void setRelativeRank(Address targetAddr, String targetNamespace, String targetName) {
			rank = 0;
			if (targetAddr != null) {
				Address myAddr = extLoc.getAddress();
				if (myAddr != null && targetAddr.equals(extLoc.getAddress())) {
					rank += 3; // address match
				}
				else if (myAddr != null) {
					// If memory addresses both specified and differ - reduce rank
					rank -= 3;
				}
			}
			if (targetName != null && targetName.equals(getSymbolName())) {
				rank += 2; // non-default name match
				if (targetNamespace != null && targetNamespace.equals(getFullNamespaceName())) {
					rank += 1; // non-default namespace match improves name match
				}
			}
		}

	}

	/**
	 * Given an external symbol for a specified program, get the corresponding symbol,
	 * which has the same name and path,  from the specified otherProgram.<br>
	 * Note: The type of the returned symbol may be different than the type of the symbol
	 * @param program program which contains the specified symbol instance
	 * @param symbol symbol to look for
	 * @param otherProgram other program
	 * @param otherRestrictedSymbolIds an optional set of symbol ID's from the other program
	 * which will be treated as the exclusive set of candidate symbols to consider.
	 * @return corresponding external symbol for otherProgram or null if no such symbol exists.
	 */
	public static Symbol getMatchingExternalSymbol(Program program, Symbol symbol,
			Program otherProgram, Set<Long> otherRestrictedSymbolIds) {

		if (symbol == null) {
			return null;
		}
		SymbolType type = symbol.getSymbolType();
		if ((type != SymbolType.FUNCTION && type != SymbolType.LABEL) || !symbol.isExternal()) {
			return null;
		}

		ReferenceManager refMgr = program.getReferenceManager();
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocation extLoc = extMgr.getExternalLocation(symbol);

		String targetName = symbol.getSource() != SourceType.DEFAULT ? symbol.getName() : null;
		String targetNamespace = symbol.getParentNamespace().getName(true);
		if (targetNamespace.startsWith(Library.UNKNOWN)) {
			targetNamespace = null;
		}
		Address targetAddr = extLoc.getAddress();

		ReferenceManager otherRefMgr = otherProgram.getReferenceManager();
		SymbolTable otherSymbMgr = otherProgram.getSymbolTable();
		ExternalManager otherExtMgr = otherProgram.getExternalManager();

		// Process references
		ReferenceIterator refIter = refMgr.getReferencesTo(symbol.getAddress());
		HashMap<Address, ExternalReferenceCount> matchesMap = new HashMap<>();
		int totalMatchCnt = 0;
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			Reference otherRef =
				otherRefMgr.getPrimaryReferenceFrom(ref.getFromAddress(), ref.getOperandIndex());
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
				refMatch = new ExternalReferenceCount(otherExtLoc);
				refMatch.setRelativeRank(targetAddr, targetNamespace, targetName);
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
						refMatch = new ExternalReferenceCount(otherExtLoc);
						refMatch.setRelativeRank(targetAddr, targetNamespace, targetName);
						matchesMap.put(otherThunkedFunc.getEntryPoint(), refMatch);
					}
					else {
						++refMatch.refCount;
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
				boolean addIt = false;
				if (targetAddr != null) {
					ExternalLocation otherExtLoc = otherExtMgr.getExternalLocation(otherSym);
					Address otherAddr = otherExtLoc.getAddress();
					if (otherAddr != null && targetAddr.equals(otherAddr) &&
						originalNamesDontConflict(extLoc, otherExtLoc)) {
						addIt = true;
					}
				}
				if (!addIt && targetName != null && targetName.equals(otherSym.getName())) {
					addIt = true;
				}
				if (addIt) {
					ExternalReferenceCount refMatch =
						new ExternalReferenceCount(otherExtMgr.getExternalLocation(otherSym));
					refMatch.setRelativeRank(targetAddr, targetNamespace, targetName);
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

	private static boolean originalNamesDontConflict(ExternalLocation extLoc,
			ExternalLocation otherExtLoc) {
		if (extLoc.getOriginalImportedName() == null) {
			return true;
		}
		if (otherExtLoc.getOriginalImportedName() == null) {
			return true;
		}
		return extLoc.getOriginalImportedName().equals(otherExtLoc.getOriginalImportedName());
	}

	/**
	 * Given an external location for a specified program, get the corresponding external location,
	 * which has the same name and path,  from the specified otherProgram.<br>
	 * Note: The type of the returned external location may be different than the type of the
	 * original external location.
	 * @param program program which contains the specified external location instance
	 * @param externalLocation external location to look for
	 * @param otherProgram other program
	 * @return corresponding external location for otherProgram or null if no such external location exists.
	 */
	public static ExternalLocation getMatchingExternalLocation(Program program,
			ExternalLocation externalLocation, Program otherProgram) {
		if (externalLocation == null) {
			return null;
		}
		Symbol symbol = externalLocation.getSymbol();
		if (symbol == null) {
			return null;
		}
		Symbol matchingExternalSymbol =
			getMatchingExternalSymbol(program, symbol, otherProgram, null);
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
