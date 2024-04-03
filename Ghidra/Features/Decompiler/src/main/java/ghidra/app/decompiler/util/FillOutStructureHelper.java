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
package ghidra.app.decompiler.util;

import java.util.*;
import java.util.Map.Entry;

import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Automatically creates a structure definition based on the references found by the decompiler.
 *
 * If the parameter is already a structure pointer, any new references found will be added
 * to the structure, even if the structure must grow.
 *
 */
public class FillOutStructureHelper {

	/**
	 * Varnode with data-flow traceable to original pointer
	 */
	private static class PointerRef {
		Varnode varnode;		// The traced Varnode
		long offset;			// Offset relative to original pointer

		public PointerRef(Varnode ref, long off) {
			varnode = ref;
			offset = off;
		}
	}

	private static final String DEFAULT_BASENAME = "astruct";
	private static final String DEFAULT_CATEGORY = "/auto_structs";

	private Program currentProgram;
	private TaskMonitor monitor;
	private DecompileOptions decompileOptions;

	private static final int maxCallDepth = 1;

	private int currentCallDepth;		// Current call depth (from root function)
	private NoisyStructureBuilder componentMap = new NoisyStructureBuilder();
	private HashMap<Address, Address> addressToCallInputMap = new HashMap<>();
	private List<OffsetPcodeOpPair> storePcodeOps = new ArrayList<>();
	private List<OffsetPcodeOpPair> loadPcodeOps = new ArrayList<>();

	/**
	 * Constructor.
	 * 
	 * @param program the current program
	 * @param decompileOptions decompiler options 
	 *   (see {@link DecompilerUtils#getDecompileOptions(ServiceProvider, Program)})
	 * @param monitor task monitor
	 */
	public FillOutStructureHelper(Program program, DecompileOptions decompileOptions,
			TaskMonitor monitor) {
		this.currentProgram = program;
		this.decompileOptions = decompileOptions;
		this.monitor = monitor;
	}

	/**
	 * Method to create a structure data type for a variable in the given function.
	 * Unlike the applyTo() action, this method will not modify the function, its variables,
	 * or any existing data-types. A new structure is always created.
	 * @param var a parameter, local variable, or global variable used in the given function
	 * @param function the function to process
	 * @param createNewStructure if true a new structure with a unique name will always be generated,
	 * if false and variable corresponds to a structure pointer the existing structure will be 
	 * updated instead.
	 * @param createClassIfNeeded if true and variable corresponds to a <B>this</B> pointer without 
	 * an assigned Ghidra Class (i.e., {@code void * this}), the function will be assigned to a 
	 * new unique Ghidra Class namespace with a new identically named structure returned.  If false,
	 * a new uniquely structure will be created.
	 * @return a filled-in structure or null if one could not be created
	 */
	public Structure processStructure(HighVariable var, Function function,
			boolean createNewStructure, boolean createClassIfNeeded) {

		if (var == null || var.getSymbol() == null || var.getOffset() >= 0) {
			return null;
		}

		init();

		Structure structDT = null;

		if (!createNewStructure) {
			structDT = getStructureForExtending(var.getDataType());
			if (structDT != null) {
				componentMap.populateOriginalStructure(structDT);
			}
		}

		fillOutStructureDef(var);
		pushIntoCalls();

		long size = componentMap.getSize();
		if (size == 0) {
			return null;
		}
		if (size < 0 || size > Integer.MAX_VALUE) {
			Msg.error(this, "Computed structure length out-of-range: " + size);
			return null;
		}

		if (structDT == null) {
			if (createClassIfNeeded && DecompilerUtils.testForAutoParameterThis(var, function)) {
				structDT = createUniqueClassNamespaceAndStructure(var, (int) size, function);
			}
			else {
				structDT = createUniqueStructure((int) size);
			}
		}
		else {
			expandStructureSizeIfNeeded(structDT, (int) size);
		}

		populateStructure(structDT);

		return structDT;
	}

	private void expandStructureSizeIfNeeded(Structure struct, int size) {
		// TODO: How should an existing packed structure be handled? Growing and offset-based 
		// placement does not apply
		int len = struct.isZeroLength() ? 0 : struct.getLength();
		if (size > len) {
			struct.growStructure(size - len);
		}
	}

	private void init() {
		currentCallDepth = 0;		// Current call depth (from root function)
		componentMap = new NoisyStructureBuilder();
		addressToCallInputMap = new HashMap<>();
		storePcodeOps = new ArrayList<>();
		loadPcodeOps = new ArrayList<>();
	}

	/**
	 * Retrieve the component map that was generated when structure was created using decomiler info.
	 * Results are not valid until {@link #processStructure(HighVariable, Function, boolean)} is invoked.
	 * @return componentMap
	 */
	public NoisyStructureBuilder getComponentMap() {
		return componentMap;
	}

	/**
	 * Retrieve the offset/pcodeOp pairs that are used to store data into the variable
	 * used to fill-out structure.
	 * Results are not valid until {@link #processStructure(HighVariable, Function, boolean)} is invoked.
	 * @return the pcodeOps doing the storing to the associated variable
	 */
	public List<OffsetPcodeOpPair> getStorePcodeOps() {
		return storePcodeOps;
	}

	/**
	 * Retrieve the offset/pcodeOp pairs that are used to load data from the variable
	 * used to fill-out structure.
	 * Results are not valid until {@link #processStructure(HighVariable, Function, boolean)} is invoked.
	 * @return the pcodeOps doing the loading from the associated variable
	 */
	public List<OffsetPcodeOpPair> getLoadPcodeOps() {
		return loadPcodeOps;
	}

	/**
	 * Retrieve the (likely) storage address of a function parameter given
	 * the inputs to a CALL p-code op and particular Varnode slot within the inputs.
	 * We compute the address from the point of view of the called function (callee)
	 * which may be different from the point of view of the caller, which may be
	 * different from the address of the Varnode currently holding the parameter.
	 * @param inputs is the array of Varnode inputs to the CALL
	 * @param slot is the index of the Varnode holding the parameter we want.
	 * @return the starting address of the parameter or null if the address can't be identified
	 */
	private Address computeParamAddress(Varnode[] inputs, int slot) {
		Address funcAddr = inputs[0].getAddress();
		Function function = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
		if (function == null) {
			return null;
		}
		Parameter[] parameters = function.getParameters();
		if (slot - 1 < parameters.length) {
			return parameters[slot - 1].getMinAddress();
		}
		PrototypeModel model = function.getCallingConvention();
		if (model == null) {
			model = currentProgram.getCompilerSpec().getDefaultCallingConvention();
			if (model == null) {
				return null;
			}
		}
		DataType typeList[] = new DataType[slot + 1];
		typeList[0] = DataType.DEFAULT;		// Default function return data-type
		for (int i = 1; i < slot + 1; ++i) {
			typeList[i] = inputs[i].getHigh().getDataType();
		}
		VariableStorage[] storageLocations =
			model.getStorageLocations(currentProgram, typeList, false);
		return storageLocations[slot].getMinAddress();
	}

	/**
	 * Recursively visit calls that take the structure pointer as a parameter.
	 * Add any new references to the offsetToDataTypeMap.
	 */
	private void pushIntoCalls() {
		AddressSet doneSet = new AddressSet();

		while (addressToCallInputMap.size() > 0) {
			currentCallDepth += 1;
			if (currentCallDepth > maxCallDepth) {
				return;
			}
			HashMap<Address, Address> savedList = addressToCallInputMap;
			addressToCallInputMap = new HashMap<>();
			Set<Address> keys = savedList.keySet();
			for (Address addr : keys) {
				if (doneSet.contains(addr)) {
					continue;
				}
				doneSet.addRange(addr, addr);
				Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
				Address storageAddr = savedList.get(addr);
				HighVariable paramHighVar = computeHighVariable(storageAddr, func);
				if (paramHighVar != null) {
					fillOutStructureDef(paramHighVar);
				}
			}
		}
	}

	/**
	 * Decompile a function and return the resulting HighVariable associated with a storage address
	 * @param storageAddress the storage address of the variable
	 * @param function is the function
	 * @return the corresponding HighVariable or null
	 */
	public HighVariable computeHighVariable(Address storageAddress, Function function) {
		if (storageAddress == null) {
			return null;
		}
		DecompInterface decomplib = setUpDecompiler();
		HighVariable highVar = null;

		// call decompiler to get syntax tree
		try {
			if (!decomplib.openProgram(currentProgram)) {
				return null;
			}

			DecompileResults results = decomplib.decompileFunction(function,
				decomplib.getOptions().getDefaultTimeout(), monitor);
			if (monitor.isCancelled()) {
				return null;
			}

			HighFunction highFunc = results.getHighFunction();

			// no decompile...
			if (highFunc == null) {
				return null;
			}

			// try to map the variable
			HighSymbol sym =
				highFunc.getMappedSymbol(storageAddress, function.getEntryPoint().subtractWrap(1L));
			if (sym == null) {
				sym = highFunc.getMappedSymbol(storageAddress, null);
			}
			if (sym == null) {
				sym = highFunc.getMappedSymbol(storageAddress, function.getEntryPoint());
			}
			if (sym == null) {
				sym = highFunc.getLocalSymbolMap()
						.findLocal(storageAddress, function.getEntryPoint().subtractWrap(1L));
			}
			if (sym == null) {
				sym = highFunc.getLocalSymbolMap().findLocal(storageAddress, null);
			}
			if (sym == null) {
				sym = highFunc.getLocalSymbolMap()
						.findLocal(storageAddress, function.getEntryPoint());
			}
			if (sym == null) {
				return null;
			}

			highVar = sym.getHighVariable();
		}
		finally {
			decomplib.dispose();
		}

		return highVar;
	}

	/**
	 * Set up a decompiler interface for recovering data-flow
	 * @return the decompiler interface
	 */
	private DecompInterface setUpDecompiler() {
		DecompInterface decomplib = new DecompInterface();
		decomplib.setOptions(decompileOptions);
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		return decomplib;
	}

	/**
	 * Populate the given structure with any new discovered components in the
	 * offsetToDataTypeMap.
	 * @param structDT is the given structure
	 */
	private void populateStructure(Structure structDT) {
		Iterator<Entry<Long, DataType>> iterator = componentMap.iterator();
		while (iterator.hasNext()) {
			Entry<Long, DataType> entry = iterator.next();
			Long key = entry.getKey();
			DataType valDT = entry.getValue();
			if (key.intValue() < 0) {
				// println("    BAD OFFSET : " + key.intValue());
				continue;
			}

			// TODO: need to do data type conflict resolution
			if (structDT.getLength() < (key.intValue() + valDT.getLength())) {
				continue;
			}

			try {
				DataTypeComponent existing = structDT.getComponentAt(key.intValue());
				// try to preserve existing information.
				String name = null;
				String comment = null;
				if (existing != null) {
					name = existing.getFieldName();
					comment = existing.getComment();
				}
				structDT.replaceAtOffset(key.intValue(), valDT, valDT.getLength(), name, comment);
			}
			catch (IllegalArgumentException e) {
				Msg.debug(this, "Unexpected error changing structure offset", e);
			}
		}
	}

	/**
	 * Create a new structure of a given size and unique generated name within the DEFAULT_CATEGORY. 
	 * 
	 * @param size is the desired structure size
	 * @return the new Structure
	 */
	private Structure createUniqueStructure(int size) {
		ProgramBasedDataTypeManager dtm = currentProgram.getDataTypeManager();
		String structName = dtm.getUniqueName(new CategoryPath(DEFAULT_CATEGORY), DEFAULT_BASENAME);
		StructureDataType dt =
			new StructureDataType(new CategoryPath(DEFAULT_CATEGORY), structName, size, dtm);
		return dt;
	}

	/**
	 * Create new unique Ghidra Class namespace and corresponding structure.
	 * @param var {@code "this"} pointer variable
	 * @param size structure size
	 * @param f Ghidra Class member function
	 * @return new Ghidra Class structure or null on error
	 */
	private Structure createUniqueClassNamespaceAndStructure(HighVariable var, int size,
			Function f) {
		Namespace newNamespace = createUniqueClassName();
		if (newNamespace == null) {
			return null;
		}

		// Move function into new Ghidra Class namespace
		RenameLabelCmd command =
			new RenameLabelCmd(f.getSymbol(), f.getName(), newNamespace, SourceType.USER_DEFINED);
		if (!command.applyTo(currentProgram)) {
			return null;
		}

		// Allocate new Ghidra Class structure
		Structure structDT = VariableUtilities.findOrCreateClassStruct(f);
		if (structDT == null) {
			return null;
		}

		expandStructureSizeIfNeeded(structDT, size);

		return structDT;
	}

	private boolean programContainsNamedStructure(String structName) {
		ProgramBasedDataTypeManager dtm = currentProgram.getDataTypeManager();
		List<DataType> list = new ArrayList<>();
		dtm.findDataTypes(structName, list, true, monitor);
		for (DataType dt : list) {
			if (dt instanceof Structure) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Generate a unique Ghidra Class which does not have an existing structure
	 * @return new unique Ghidra Class namespace or null on error
	 */
	private Namespace createUniqueClassName() {
		Namespace rootNamespace = currentProgram.getGlobalNamespace();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		String newClassBase = "AutoClass";
		String newClassName;
		int index = 1;
		while (true) {
			// cycle until we find unused class/structure name
			newClassName = newClassBase + Integer.toString(index++);
			if (symbolTable.getNamespace(newClassName, rootNamespace) == null &&
				!programContainsNamedStructure(newClassName)) {
				break;
			}
		}
		// Create the class
		try {
			return symbolTable.createClass(rootNamespace, newClassName, SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			// unexpected unless possible race condition
			Msg.error(this, "Error creating class '" + newClassName + "'", e);
		}
		return null;
	}

	private boolean sanityCheck(long offset, long existingSize) {

		if (offset < 0) {
			return false; // offsets shouldn't be negative
		}
		if (offset < existingSize) {
			return true; // we have room in the structure
		}
		if (offset > 0x1000) {
			return false; // bigger than existing size; arbitrary cut-off to prevent huge structures
		}
		return true;
	}

	/**
	 * Look for Varnode references that are equal to the given variable plus a
	 * constant offset and store them in the componentMap. The search is performed
	 * by following data-flow paths starting at the given variable. If the variable flows
	 * into a CALL instruction, put it in the addressToCallInputMap if offset is 0.
	 * @param var is the given variable
	 */
	private void fillOutStructureDef(HighVariable var) {
		Varnode startVN = var.getRepresentative();
		ArrayList<PointerRef> todoList = new ArrayList<>();
		HashSet<Varnode> doneList = new HashSet<>();

		todoList.add(new PointerRef(startVN, 0));	// Base Varnode on the todo list
		Varnode[] instances = var.getInstances();
		for (Varnode vn : instances) {
			doneList.add(vn);		// Mark instances as done to avoid recursion issues
			if (vn != startVN) {
				todoList.add(new PointerRef(vn, 0));	// Make sure all instances are on the todo list
			}
		}

		// while Todo list not empty
		while (!todoList.isEmpty()) {
			PointerRef currentRef = todoList.remove(0);
			if (currentRef.varnode == null) {
				continue;
			}

			Iterator<PcodeOp> descendants = currentRef.varnode.getDescendants();
			while (descendants.hasNext()) {
				PcodeOp pcodeOp = descendants.next();
				Varnode output = pcodeOp.getOutput();
				Varnode[] inputs = pcodeOp.getInputs();
				// println("off=" + offset + "     " + pcodeOp.getSeqnum().getTarget().toString() + " : "
				//		+ pcodeOp.toString());

				DataType outDt;
				long newOff;
				switch (pcodeOp.getOpcode()) {
					case PcodeOp.INT_SUB:
					case PcodeOp.INT_ADD:
						if (!inputs[1].isConstant()) {
							break;
						}
						long value = getSigned(inputs[1]);
						newOff = currentRef.offset +
							((pcodeOp.getOpcode() == PcodeOp.INT_ADD) ? value : (-value));
						if (sanityCheck(newOff, componentMap.getSize())) { // should this offset create a location in the structure?
							putOnList(output, newOff, todoList, doneList);
							// Don't do componentMap.addDataType() as data-type info here is likely uninformed
							componentMap.setMinimumSize(newOff);
						}
						break;
					case PcodeOp.PTRADD:
						if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
							break;
						}
						newOff = currentRef.offset + getSigned(inputs[1]) * inputs[2].getOffset();
						if (sanityCheck(newOff, componentMap.getSize())) { // should this offset create a location in the structure?
							putOnList(output, newOff, todoList, doneList);
							// Don't do componentMap.addReference() as data-type info here is likely uninformed
							componentMap.setMinimumSize(newOff);
						}
						break;
					case PcodeOp.PTRSUB:
						if (!inputs[1].isConstant()) {
							break;
						}
						long subOff = currentRef.offset + getSigned(inputs[1]);
						if (sanityCheck(subOff, componentMap.getSize())) { // should this offset create a location in the structure?
							putOnList(output, subOff, todoList, doneList);
							// Don't do componentMap.addReference() as data-type info here is likely uninformed
							componentMap.setMinimumSize(subOff);
						}
						break;
					case PcodeOp.SEGMENTOP:
						// treat segment op as if it were a cast to complete the value
						//   The segment adds in some unknown base value.
						// get output and add to the Varnode Todo list
						putOnList(output, currentRef.offset, todoList, doneList);
						componentMap.setMinimumSize(currentRef.offset);
						break;
					case PcodeOp.LOAD:
						outDt = DecompilerUtils.getDataTypeTraceForward(output);
						componentMap.addDataType(currentRef.offset, outDt);

						if (outDt != null) {
							loadPcodeOps.add(new OffsetPcodeOpPair(currentRef.offset, pcodeOp));
						}

						break;
					case PcodeOp.STORE:
						// create a location in the struct
						//use the type of the varnode being put in to the structure
						if (pcodeOp.getSlot(currentRef.varnode) != 1) {
							break; // store must be into the target structure
						}
						outDt = DecompilerUtils.getDataTypeTraceBackward(inputs[2]);
						componentMap.addDataType(currentRef.offset, outDt);

						if (outDt != null) {
							storePcodeOps.add(new OffsetPcodeOpPair(currentRef.offset, pcodeOp));
						}

						break;
					case PcodeOp.CAST:
						putOnList(output, currentRef.offset, todoList, doneList);
						break;
					case PcodeOp.MULTIEQUAL:
						putOnList(output, currentRef.offset, todoList, doneList);
						break;
					case PcodeOp.COPY:
						putOnList(output, currentRef.offset, todoList, doneList);
						break;
					case PcodeOp.CALL:
						if (currentRef.offset == 0) {		// If pointer is passed directly (no offset)
							// find it as an input
							int slot = pcodeOp.getSlot(currentRef.varnode);
							if (slot > 0 && slot < pcodeOp.getNumInputs()) {
								Address storageAddr = computeParamAddress(inputs, slot);
								if (storageAddr != null) {
									addressToCallInputMap.put(inputs[0].getAddress(), storageAddr);
								}
							}
						}
						else {
							outDt = DecompilerUtils.getDataTypeTraceBackward(currentRef.varnode);
							componentMap.addReference(currentRef.offset, outDt);
						}
						break;
					case PcodeOp.CALLIND:
						outDt = DecompilerUtils.getDataTypeTraceBackward(currentRef.varnode);
						componentMap.addReference(currentRef.offset, outDt);
						break;
				}

			}
		}
	}

	private long getSigned(Varnode varnode) {
		long mask = 0x80L << ((varnode.getSize() - 1) * 8);
		long value = varnode.getOffset();
		if ((value & mask) != 0) {
			value |= (0xffffffffffffffffL << ((varnode.getSize() - 1) * 8));
		}
		return value;
	}

	/**
	 * Add a Varnode reference to the current work list to facilitate flow tracing.
	 * To prevent cycles, a separate of visited Varnodes is maintained
	 * @param output is the Varnode at the current point of flow
	 * @param offset is the relative offset of the Varnode to the root variable
	 * @param todoList is the current work list
	 * @param doneList is the visited list
	 */
	private void putOnList(Varnode output, long offset, ArrayList<PointerRef> todoList,
			HashSet<Varnode> doneList) {
		if (doneList.contains(output)) {
			return;
		}
		todoList.add(new PointerRef(output, offset));
		doneList.add(output);
	}

	/**
	 * Check if a variable has a data-type that is suitable for being extended.
	 * If so return the structure data-type, otherwise return null.
	 * Modulo typedefs, the data-type of the variable must be exactly a
	 * "pointer to a structure".  Not a "structure" itself, or a
	 * "pointer to a pointer to ... a structure".
	 * @param dt is the data-type of the variable to test
	 * @return the extendable structure data-type or null
	 */
	public static Structure getStructureForExtending(DataType dt) {
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Pointer) {
			dt = ((Pointer) dt).getDataType();
		}
		else {
			return null;
		}
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Structure) {
			return (Structure) dt;
		}
		return null;
	}

	/**
	 * Class to create pair between an offset and its related PcodeOp
	 */
	static public class OffsetPcodeOpPair {

		private Long offset;
		private PcodeOp pcodeOp;

		public OffsetPcodeOpPair(Long offset, PcodeOp pcodeOp) {
			this.offset = offset;
			this.pcodeOp = pcodeOp;
		}

		public Long getOffset() {
			return offset;
		}

		public PcodeOp getPcodeOp() {
			return pcodeOp;
		}
	}
}
