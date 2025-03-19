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
package ghidra.pcodeCPort.translate;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.address.RangeList;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.pcodeCPort.utils.AddrSpaceToIdSymmetryMap;
import ghidra.program.model.lang.SpaceNames;

public abstract class Translate implements BasicSpaceProvider {

	// NOTE: Use of FloatFormat and Pcode emit support was removed as these are
	// only required for the decompiler's implementation

	private long unique_base; // Starting offset into unique space

	private List<AddrSpace> baselist = new ArrayList<>(); // Every space we know about for this architecture
	private AddrSpace constantspace; // Quick reference to constant space
	private AddrSpace defaultspace; // Generally primary RAM, where assembly pointers point to
	private AddrSpace iopspace;
	private AddrSpace fspecspace;
	private AddrSpace stackspace;
	private AddrSpace uniqspace;
	private VectorSTL<VectorSTL<VarnodeData>> spacebaselist = new VectorSTL<>();
	protected RangeList nohighptr = new RangeList(); // Ranges for which high-level pointers are not possible
	protected int alignment; // Byte modulo on which instructions are aligned
	protected int target_endian; // =0 target is little endian =1 target is big

	/**
	 * The unique address space, for allocating temporary registers,
	 * is used for both registers needed by the pcode translation
	 * engine and, later, by the simplification engine.  This routine
	 * sets the boundary of the portion of the space allocated
	 * for the pcode engine, and sets the base offset where registers
	 * created by the simplification process can start being allocated.
	 * @param val is the boundary offset
	 */
	protected void setUniqueBase(long val) {
		if (val > unique_base) {
			unique_base = val;
		}
	}

	/**
	 * Processors can usually be described as using a big endian
	 * encoding or a little endian encoding. This routine returns
	 * true if the processor globally uses big endian encoding.
	 * @return true if big endian
	 */
	public boolean isBigEndian() {
		return target_endian == 1;
	}

	/**
	 * This routine is intended to return a global address size for the processor.
	 * @return the size of addresses in bytes
	 * @deprecated use {@link #getDefaultSize()} instead
	 */
	@Deprecated
	public int getAddrSize() {
		return defaultspace.getAddrSize();
	}

	/**
	 * Return the size of addresses for the processor's official
	 * default space. This space is usually the main RAM databus.
	 * @return the size of an address in bytes
	 */
	public int getDefaultSize() {
		return defaultspace.getAddrSize();
	}

	/**
	 * If machine instructions need to have a specific alignment
	 * for this processor, this routine returns it. I.e. a return
	 * value of 4, means that the address of all instructions
	 * must be a multiple of 4. If there is no
	 * specific alignment requirement, this routine returns 1.
	 * @return the instruction alignment
	 */
	int getAlignment() {
		return alignment;
	}

	/**
	 * This routine gets the base offset, within the unique
	 * temporary register space, where new registers can be
	 * allocated for the simplification process.  Locations before
	 * this offset are reserved registers needed by the pcode
	 * translation engine.
	 * @return the first allocatable offset
	 */
	public long getUniqueBase() {
		return unique_base;
	}

	/**
	 * There is a special address space reserved for encoding pointers
	 * to pcode operations as addresses.  This allows a direct pointer
	 * to be hidden within an operation, when manipulating pcode
	 * internally. (See IopSpace)
	 * @return a pointer to the address space
	 */
	public AddrSpace getIopSpace() {
		return iopspace;
	}

	/**
	 * There is a special address space reserved for encoding pointers
	 * to the FuncCallSpecs object as addresses. This allows direct
	 * pointers to be hidden within an operation, when manipulating
	 * pcode internally. (See FspecSpace)
	 * @return a pointer to the address space
	 */
	public AddrSpace getFspecSpace() {
		return fspecspace;
	}

	/**
	 * Most processors have registers and instructions that are
	 * reserved for implementing a stack. In the pcode translation,
	 * these are translated into locations and operations on a
	 * dedicated stack address space. (See SpacebaseSpace)
	 * @return a pointer to the stack space
	 */
	public AddrSpace getStackSpace() {
		return stackspace;
	}

	/**
	 * Both the pcode translation process and the simplification
	 * process need access to a pool of temporary registers that
	 * can be used for moving data around without affecting the
	 * address spaces used to formally model the processor's RAM
	 * and registers.  These temporary locations are all allocated
	 * from a dedicated address space, referred to as the unique
	 * space. (See UniqueSpace)
	 * @return a pointer to the unique space
	 */
	public AddrSpace getUniqueSpace() {
		return uniqspace;
	}

	/**
	 * Most processors have a main address bus, on which the bulk
	 * of the processor's RAM is mapped.  Everything referenced
	 * with this address bus should be modeled in pcode with a
	 * single address space, referred to as the default space.
	 * @return a pointer to the default space
	 */
	@Override
	public AddrSpace getDefaultSpace() {
		return defaultspace;
	}

	/**
	 * Pcode represents constant values within an operation as
	 * offsets within a special constant address space. 
	 * (See ConstantSpace)
	 * @return a pointer to the constant space
	 */
	@Override
	public AddrSpace getConstantSpace() {
		return constantspace;
	}

	/**
	 * This routine encodes a specific value as a constant
	 * address. I.e. the address space of the resulting Address
	 * will be the constant space, and the offset will be the
	 * value.
	 * @param val is the constant value to encode
	 * @return the constant address
	 */
	public Address getConstant(long val) {
		return new Address(constantspace, val);
	}

	/**
	 * This routine is used to encode a pointer to an address space
	 * as a constant Address, for use in LOAD and STORE
	 * operations.  This is used internally and is slightly more
	 * efficient than storing the formal index of the space
	 * @param spc is the space pointer to be encoded
	 * @return the encoded Address
	 */
	public Address createConstFromSpace(AddrSpace spc) {
		long id = AddrSpaceToIdSymmetryMap.getID(spc);
		return new Address(constantspace, id);
	}

	/**
	 * This returns the total number of address spaces used by the
	 * processor, including all special spaces, like the constant
	 * space and the iop space. 
	 * @return the number of spaces
	 */
	public int numSpaces() {
		return baselist.size();
	}

	/**
	 * This retrieves a specific address space via its formal index.
	 * All spaces have an index, and in conjunction with the numSpaces
	 * method, this method can be used to iterate over all spaces.
	 * @param i is the index of the address space
	 * @return a pointer to the desired space
	 */
	public AddrSpace getSpace(int i) {
		return baselist.get(i);
	}

	/**
	 * The Translate object keep tracks of address ranges for which
	 * it is effectively impossible to have a pointer into. This is
	 * used for pointer aliasing calculations.  This routine returns
	 * true if it is possible to have pointers into the indicated
	 * range.
	 * @param loc is the starting address of the range
	 * @param size is the size of the range in bytes
	 * @return true if pointers are possible
	 */
	public boolean highPtrPossible(Address loc, int size) {
		return !nohighptr.inRange(loc, size);
	}

	protected void registerContext(String name, int sbit, int ebit) {
		// Base implementation (for compiling) doesn't need to keep track of context symbol
	}

//	public void setContextDefault(String name, int val) {
//	}

	public abstract VarnodeData getRegister(String nm);

	public abstract String getRegisterName(AddrSpace base, long off, int size);

	public abstract void getUserOpNames(VectorSTL<String> res);

	public abstract int instructionLength(Address baseaddr);

	public abstract int printAssembly(PrintStream s, int size, Address baseaddr);

	public Translate() {
		unique_base = 0;
		alignment = 1;
	}

	public AddrSpace getSpaceByName(String nm) { // Convert name to space
		for (AddrSpace space : baselist) {
			if (space.getName().equals(nm)) {
				return space;
			}
		}
		return null;
	}

	public AddrSpace getSpaceByShortcut(char sc) {
		for (AddrSpace space : baselist) {
			if (space.getShortCut() == sc) {
				return space;
			}
		}
		return null;
	}

	/**
	 * Associate a particular register or memory location with an address space
	 * The canonical example is the stack pointer and the stack space.
	 * The basespace is the so-called stack space, which is really a
	 * virtual space typically contained by ram space.  The spacebase
	 * register effectively hides the true location of its basespace with
	 * its containing space and facilitates addressing in the virtual space
	 * by providing a base offset into the containing space.
	 * @param basespace is the virtual address space
	 * @param spc is the address space of the register
	 * @param offset is the offset of the register
	 * @param size is the size of the register
	 */
	public void addSpacebase(AddrSpace basespace, AddrSpace spc, long offset, int size) {
		int index = basespace.getIndex();
		while (index >= spacebaselist.size()) {
			spacebaselist.push_back(new VectorSTL<VarnodeData>());
		}

		VectorSTL<VarnodeData> datalist = spacebaselist.get(index);
		datalist.push_back(new VarnodeData());
		datalist.back().space = spc;
		datalist.back().offset = offset;
		datalist.back().size = size;
	}

	/**
	 * If basespace is a virtual space, it has one (or more) registers or memory locations
	 * associated with it that serve as base offsets, anchoring the virtual space in a physical space
	 * @param basespace is the virtual space to check
	 * @return the number of spacebase registers
	 */
	public int numSpacebase(AddrSpace basespace) {
		int index = basespace.getIndex();
		if (index >= spacebaselist.size()) {
			return 0;
		}
		return spacebaselist.get(index).size();
	}

	/**
	 * Retrieve a particular spacebase register associated with the virtual address space
	 * basespace.  This register serves as a base offset to anchor basespace within
	 * its containing space.
	 * @param basespace is the virtual space to find a spacebase register for
	 * @param i is the index of the particular spacebase register
	 * @return a reference to the spacebase register
	 */
	public VarnodeData getSpacebase(AddrSpace basespace, int i) {
		int index = basespace.getIndex();
		if (index < spacebaselist.size()) {
			VectorSTL<VarnodeData> datalist = spacebaselist.get(index);
			if (i < datalist.size()) {
				return datalist.get(i);
			}
		}
		throw new LowlevelError(
			"Space base register does not exist for space: " + basespace.getName());
	}

	public void insertSpace(AddrSpace spc) { // Add new space to the list, verify name and id conventions
		boolean nametype_mismatch = false;
		boolean duplicatedefine = false;
		switch (spc.getType()) {
			case IPTR_CONSTANT:
				if (!spc.getName().equals(SpaceNames.CONSTANT_SPACE_NAME)) {
					nametype_mismatch = true;
				}
				if (baselist.size() != 0) {
					throw new LowlevelError("const space must be initialized first");
				}
				constantspace = spc;
				break;
			case IPTR_INTERNAL:
				if (!spc.getName().equals(SpaceNames.UNIQUE_SPACE_NAME)) {
					nametype_mismatch = true;
				}
				if (uniqspace != null) {
					duplicatedefine = true;
				}
				uniqspace = spc;
				break;
			case IPTR_FSPEC:
				if (!spc.getName().equals(SpaceNames.FSPEC_SPACE_NAME)) {
					nametype_mismatch = true;
				}
				if (fspecspace != null) {
					duplicatedefine = true;
				}
				fspecspace = spc;
				break;
			case IPTR_IOP:
				if (!spc.getName().equals(SpaceNames.IOP_SPACE_NAME)) {
					nametype_mismatch = true;
				}
				if (iopspace != null) {
					duplicatedefine = true;
				}
				iopspace = spc;
				break;
			case IPTR_SPACEBASE:
				if (spc.getName().equals(SpaceNames.STACK_SPACE_NAME)) {
					if (stackspace != null) {
						duplicatedefine = true;
					}
					stackspace = spc;
				}
				// fallthru
			case IPTR_PROCESSOR:
				if (spc.isOtherSpace()) {
					if (spc.getIndex() != SpaceNames.OTHER_SPACE_INDEX) {
						throw new LowlevelError("OTHER space must be assigned index 1");
					}
				}
				for (AddrSpace space : baselist) {
					if (space.getName().equals(spc.getName())) {
						duplicatedefine = true;
					}
				}
				break;
		}
		if (nametype_mismatch) {
			throw new LowlevelError("Space " + spc.getName() + " was initialized with wrong type");
		}
		if (duplicatedefine) {
			throw new LowlevelError("Space " + spc.getName() + " was initialized more than once");
		}
		if (baselist.size() != spc.getIndex()) {
			throw new LowlevelError("Space " + spc.getName() + " was initialized with a bad id");
		}
		baselist.add(spc);
	}

	public void setDefaultSpace(int index) { // Set the default space
		if (defaultspace != null) {
			throw new LowlevelError("Default space set multiple times");
		}
		if (baselist.size() <= index) {
			throw new LowlevelError("Bad index for default space");
		}
		defaultspace = baselist.get(index);
	}

	public char assignShortcut(spacetype tp) {
		char shortcut = 'x';
		switch (tp) {
			case IPTR_CONSTANT:
				shortcut = '#';
				break;
			case IPTR_PROCESSOR:
				shortcut = 'r';
				break;
			case IPTR_SPACEBASE:
				shortcut = 's';
				break;
			case IPTR_INTERNAL:
				shortcut = 'u';
				break;
			case IPTR_FSPEC:
				shortcut = 'f';
				break;
			case IPTR_IOP:
				shortcut = 'i';
				break;
		}
		//  if ((shortcut >= 'A') && (shortcut <= 'R'))
		//    shortcut |= 0x20;

		for (int i = 0x61; i < 0x7a; ++i) {
			int j;
			for (j = 0; j < baselist.size(); ++j) {
				if (baselist.get(j).getShortCut() == shortcut) {
					break;
				}
			}
			if (j == baselist.size()) {
				return shortcut; // Found an open shortcut
			}
			shortcut = (char) i;
		}
		throw new LowlevelError("Unable to assign shortcut");
	}

	// Get space the next space in the absolute order of addresses
	public AddrSpace getNextSpaceInOrder(AddrSpace spc) {

		int nextIndex = spc.getIndex() + 1;
		if (nextIndex >= 0 && nextIndex < baselist.size()) {
			return baselist.get(nextIndex);
		}
		return AddrSpace.MAX_SPACE;
	}

	public AddrSpace getSpaceBySpacebase(Address loc, int size) { // Get space associated with spacebase register
		AddrSpace id;
		for (AddrSpace element : baselist) {
			id = element;
			int numspace = numSpacebase(id);
			for (int j = 0; j < numspace; ++j) {
				VarnodeData point = getSpacebase(id, j);
				if (point.size == size && point.space == loc.getSpace() &&
					point.offset == loc.getOffset()) {
					return id;
				}
			}
		}
		throw new LowlevelError("Unable to find entry for spacebase register");
	}

	public void dispose() {
		// TODO Auto-generated method stub

	}

	public void setLanguage(String processorFile) {
//		spaceOrderMap = SpaceOrderMap.getSpaceOrderMapForProcessor( processorFile );		
	}

//	public void allowContextSet(boolean val) {
//	}

}
