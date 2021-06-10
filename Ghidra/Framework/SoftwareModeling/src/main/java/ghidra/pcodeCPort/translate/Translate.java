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

import org.jdom.Element;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.address.*;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.utils.AddrSpaceToIdSymmetryMap;
import ghidra.pcodeCPort.xml.DocumentStorage;
import ghidra.program.model.lang.BasicCompilerSpec;

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

	/// The \e unique address space, for allocating temporary registers,
	/// is used for both registers needed by the pcode translation
	/// engine and, later, by the simplification engine.  This routine
	/// sets the boundary of the portion of the space allocated
	/// for the pcode engine, and sets the base offset where registers
	/// created by the simplification process can start being allocated.
	/// \param val is the boundary offset
	protected void setUniqueBase(long val) {
		if (val > unique_base) {
			unique_base = val;
		}
	}

	/// Processors can usually be described as using a big endian
	/// encoding or a little endian encoding. This routine returns
	/// \b true if the processor globally uses big endian encoding.
	/// \return \b true if big endian
	public boolean isBigEndian() {
		return target_endian == 1;
	}

	/// \deprecated This routine is intended to return a \e global
	/// address size for the processor. Use getDefaultSize instead.
	/// \return the size of addresses in bytes
	public int getAddrSize() {
		return defaultspace.getAddrSize();
	}

	/// Return the size of addresses for the processor's official
	/// default space. This space is usually the main RAM databus.
	/// \return the size of an address in bytes
	public int getDefaultSize() {
		return defaultspace.getAddrSize();
	}

	/// If machine instructions need to have a specific alignment
	/// for this processor, this routine returns it. I.e. a return
	/// value of 4, means that the address of all instructions
	/// must be a multiple of 4. If there is no
	/// specific alignment requirement, this routine returns 1.
	/// \return the instruction alignment
	int getAlignment() {
		return alignment;
	}

	/// This routine gets the base offset, within the \e unique
	/// temporary register space, where new registers can be
	/// allocated for the simplification process.  Locations before
	/// this offset are reserved registers needed by the pcode
	/// translation engine.
	/// \return the first allocatable offset
	public long getUniqueBase() {
		return unique_base;
	}

	/// There is a special address space reserved for encoding pointers
	/// to pcode operations as addresses.  This allows a direct pointer
	/// to be \e hidden within an operation, when manipulating pcode
	/// internally. (See IopSpace)
	/// \return a pointer to the address space
	public AddrSpace getIopSpace() {
		return iopspace;
	}

	/// There is a special address space reserved for encoding pointers
	/// to the FuncCallSpecs object as addresses. This allows direct
	/// pointers to be \e hidden within an operation, when manipulating
	/// pcode internally. (See FspecSpace)
	/// \return a pointer to the address space
	public AddrSpace getFspecSpace() {
		return fspecspace;
	}

	/// Most processors have registers and instructions that are
	/// reserved for implementing a stack. In the pcode translation,
	/// these are translated into locations and operations on a
	/// dedicated \b stack address space. (See SpacebaseSpace)
	/// \return a pointer to the \b stack space
	public AddrSpace getStackSpace() {
		return stackspace;
	}

	/// Both the pcode translation process and the simplification
	/// process need access to a pool of temporary registers that
	/// can be used for moving data around without affecting the
	/// address spaces used to formally model the processor's RAM
	/// and registers.  These temporary locations are all allocated
	/// from a dedicated address space, referred to as the \b unique
	/// space. (See UniqueSpace)
	/// \return a pointer to the \b unique space
	public AddrSpace getUniqueSpace() {
		return uniqspace;
	}

	/// Most processors have a main address bus, on which the bulk
	/// of the processor's RAM is mapped.  Everything referenced
	/// with this address bus should be modeled in pcode with a
	/// single address space, referred to as the \e default space.
	/// \return a pointer to the \e default space
	@Override
	public AddrSpace getDefaultSpace() {
		return defaultspace;
	}

	/// Pcode represents constant values within an operation as
	/// offsets within a special \e constant address space. 
	/// (See ConstantSpace)
	/// \return a pointer to the \b constant space
	@Override
	public AddrSpace getConstantSpace() {
		return constantspace;
	}

	// This routine encodes a specific value as a \e constant
	/// address. I.e. the address space of the resulting Address
	/// will be the \b constant space, and the offset will be the
	/// value.
	/// \param val is the constant value to encode
	/// \return the \e constant address
	public Address getConstant(long val) {
		return new Address(constantspace, val);
	}

	// This routine is used to encode a pointer to an address space
	// as a \e constant Address, for use in \b LOAD and \b STORE
	// operations.  This is used internally and is slightly more
	// efficient than storing the formal index of the space
	// param spc is the space pointer to be encoded
	// \return the encoded Address
	public Address createConstFromSpace(AddrSpace spc) {
		long id = AddrSpaceToIdSymmetryMap.getID(spc);
		return new Address(constantspace, id);
	}

	// This returns the total number of address spaces used by the
	// processor, including all special spaces, like the \b constant
	// space and the \b iop space. 
	// \return the number of spaces
	public int numSpaces() {
		return baselist.size();
	}

	// This retrieves a specific address space via its formal index.
	// All spaces have an index, and in conjunction with the numSpaces
	// method, this method can be used to iterate over all spaces.
	// \param i is the index of the address space
	// \return a pointer to the desired space
	public AddrSpace getSpace(int i) {
		return baselist.get(i);
	}

	// The Translate object keep tracks of address ranges for which
	// it is effectively impossible to have a pointer into. This is
	// used for pointer aliasing calculations.  This routine returns
	// \b true if it is \e possible to have pointers into the indicated
	// range.
	// \param loc is the starting address of the range
	// \param size is the size of the range in bytes
	// \return \b true if pointers are possible
	public boolean highPtrPossible(Address loc, int size) {
		return !nohighptr.inRange(loc, size);
	}

	public abstract void initialize(DocumentStorage store);

	protected void registerContext(String name, int sbit, int ebit) {
	}

	public void setContextDefault(String name, int val) {
	}

	public abstract VarnodeData getRegister(String nm);

	public abstract String getRegisterName(AddrSpace base, long off, int size);

	public abstract void getUserOpNames(VectorSTL<String> res);

	public abstract int instructionLength(Address baseaddr);

	public abstract int printAssembly(PrintStream s, int size, Address baseaddr);

	public Translate() {
		unique_base = 0;
		alignment = 1;
	}

	AddrSpace restoreXmlSpace(Element el) { // Factory for spaces
		AddrSpace res;
		String tp = el.getName();
		if ("space_base".equals(tp)) {
			res = new SpacebaseSpace(this);
		}
		else if ("space_unique".equals(tp)) {
			res = new UniqueSpace(this);
		}
		else if ("space_other".equals(tp)) {
			res = new OtherSpace(this);
		}
		else {
			res = new AddrSpace(this, spacetype.IPTR_PROCESSOR);
		}

		res.restoreXml(el);
		return res;
	}

	protected void restoreXmlSpaces(Element el) {
		// The first space should always be the constant space
		insertSpace(new ConstantSpace(this, "const", BasicCompilerSpec.CONSTANT_SPACE_INDEX));

		// The second space should always be the other space
		insertSpace(new OtherSpace(this, BasicCompilerSpec.OTHER_SPACE_NAME,
			BasicCompilerSpec.OTHER_SPACE_INDEX));

		String defname = el.getAttributeValue("defaultspace");
		List<?> children = el.getChildren();
		for (Object object : children) {
			AddrSpace spc = restoreXmlSpace((Element) object);
			insertSpace(spc);
		}
		AddrSpace spc = getSpaceByName(defname);
		setDefaultSpace(spc.getIndex());
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

	// Associate a particular register or memory location with an address space
	// The canonical example is the \b stack \b pointer and the stack space.
	// The \b basespace is the so-called stack space, which is really a
	// virtual space typically contained by ram space.  The \b spacebase
	// register effectively hides the true location of its basespace with
	// its containing space and facilitates addressing in the virtual space
	// by providing a base offset into the containing space.
	// \param basespace is the virtual address space
	// \param spc is the address space of the register
	// \param offset is the offset of the register
	// \param size is the size of the register
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

	// If \b basespace is a virtual space, it has one (or more) registers or memory locations
	// associated with it that serve as base offsets, anchoring the virtual space in a physical space
	// \param basespace is the virtual space to check
	// \return the number of spacebase registers
	public int numSpacebase(AddrSpace basespace) {
		int index = basespace.getIndex();
		if (index >= spacebaselist.size()) {
			return 0;
		}
		return spacebaselist.get(index).size();
	}

	// Retrieve a particular spacebase register associated with the virtual address space
	// \b basespace.  This register serves as a base offset to anchor \b basespace within
	// its containing space.
	// \param basespace is the virtual space to find a spacebase register for
	// \param i is the index of the particular spacebase register
	// \return a reference to the spacebase register
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
				if (!spc.getName().equals("const")) {
					nametype_mismatch = true;
				}
				if (baselist.size() != 0) {
					throw new LowlevelError("const space must be initialized first");
				}
				constantspace = spc;
				break;
			case IPTR_INTERNAL:
				if (!spc.getName().equals("unique")) {
					nametype_mismatch = true;
				}
				if (uniqspace != null) {
					duplicatedefine = true;
				}
				uniqspace = spc;
				break;
			case IPTR_FSPEC:
				if (!spc.getName().equals("fspec")) {
					nametype_mismatch = true;
				}
				if (fspecspace != null) {
					duplicatedefine = true;
				}
				fspecspace = spc;
				break;
			case IPTR_IOP:
				if (!spc.getName().equals("iop")) {
					nametype_mismatch = true;
				}
				if (iopspace != null) {
					duplicatedefine = true;
				}
				iopspace = spc;
				break;
			case IPTR_SPACEBASE:
				if (spc.getName().equals("stack")) {
					if (stackspace != null) {
						duplicatedefine = true;
					}
					stackspace = spc;
				}
				else {
				}
				// fallthru
			case IPTR_PROCESSOR:
				if (spc.isOtherSpace()) {
					if (spc.getIndex() != BasicCompilerSpec.OTHER_SPACE_INDEX) {
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

	public void parseStackPointer(Element el) {
		int ind = baselist.size();

		AddrSpace basespace = getSpaceByName(el.getAttributeValue("space"));
		if (basespace == null) {
			throw new LowlevelError("Unknown space name: " + el.getAttributeValue("space"));
		}
		AddrSpace spc;

		// Get data for the stackpointer
		VarnodeData point = getRegister(el.getAttributeValue("register"));
		spc = new SpacebaseSpace("stack", ind, point.size, basespace, point.space.getDelay() + 1);
		insertSpace(spc);
		addSpacebase(stackspace, point.space, point.offset, point.size);
	}

	public void parseSpacebase(Element el) { // Parse a "spacebase" command in configuration file
		String namestring = el.getAttributeValue("name");
		VarnodeData point = getRegister(el.getAttributeValue("register"));
		AddrSpace spc = getSpaceByName(namestring);
		if (spc == null) { // Space not previously defined
			int ind = baselist.size();

			AddrSpace basespace = getSpaceByName(el.getAttributeValue("space"));
			if (basespace == null) {
				throw new LowlevelError("Unknown space name: " + el.getAttributeValue("space"));
			}
			spc = new SpacebaseSpace(namestring, ind, point.size, basespace,
				point.space.getDelay() + 1);
			insertSpace(spc);
		}
		addSpacebase(spc, point.space, point.offset, point.size);
	}

	/**
	 * This routine is used by the initialization process to add
	 * address ranges to which there is never an (indirect) pointer
	 * Should only be called during initialization
	 * @param el is the parse XML describing the address range
	 */
	public void parseNoHighPtr(Element el) {
		List<?> list = el.getChildren();
		for (Object object : list) {
			Range range = new Range();
			range.restoreXml((Element) object, this);
			nohighptr.insertRange(range.getSpace(), range.getFirst(), range.getLast());
		}
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

	public void allowContextSet(boolean val) {
	}

}
