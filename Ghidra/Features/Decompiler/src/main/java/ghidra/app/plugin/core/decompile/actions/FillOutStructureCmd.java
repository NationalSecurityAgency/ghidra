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
package ghidra.app.plugin.core.decompile.actions;

import java.util.*;
import java.util.Map.Entry;

import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.decompiler.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Automatically creates a structure definition based on the references found by the decompiler.
 *
 * If the parameter is already a structure pointer, any new references found will be added
 * to the structure, even if the structure must grow.
 *
 */
public class FillOutStructureCmd extends BackgroundCommand {

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

	private int currentCallDepth = 0;		// Current call depth (from root function)
	private int maxCallDepth = 1;

	private NoisyStructureBuilder componentMap = new NoisyStructureBuilder();
	private HashMap<Address, Address> addressToCallInputMap = new HashMap<>();

	private Program currentProgram;
	private ProgramLocation currentLocation;
	private Function rootFunction;
	private TaskMonitor monitor;
	private PluginTool tool;

	private List<OffsetPcodeOpPair> storePcodeOps = new ArrayList<>();
	private List<OffsetPcodeOpPair> loadPcodeOps = new ArrayList<>();

	/**
	 * Constructor.
	 * 
	 * @param program the current program
	 * @param location the current program location
	 * @param tool the current plugin tool
	 */
	public FillOutStructureCmd(Program program, ProgramLocation location, PluginTool tool) {
		super("Fill Out Structure", true, false, true);
		this.tool = tool;
		this.currentProgram = program;
		this.currentLocation = Objects.requireNonNull(location);
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
		this.monitor = taskMonitor;

		rootFunction =
			currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
		if (rootFunction == null) {
			return false;
		}

		int transaction = currentProgram.startTransaction("Fill Out Structure Variable");
		try {
			HighVariable var = null;

			if (!(currentLocation instanceof DecompilerLocation)) {
				// if we don't have one, make one, and map variable to a varnode
				Address storageAddr = computeStorageAddress(currentLocation, rootFunction);
				var = computeHighVariable(storageAddr, rootFunction);
			}
			else {

				// get the Varnode under the cursor
				DecompilerLocation dloc = (DecompilerLocation) currentLocation;
				ClangToken token = dloc.getToken();
				if (token == null) {
					return false;
				}

				var = token.getHighVariable();
				Varnode exactSpot = token.getVarnode();

				if ((var != null) && (exactSpot != null)) {
					HighFunction hfunc = var.getHighFunction();
					try { // Adjust HighVariable based on exact varnode selected, if there are merged groups
						var = hfunc.splitOutMergeGroup(var, exactSpot);
					}
					catch (PcodeException ex) {
						return false;
					}
				}
			}

			if (var == null || var.getSymbol() == null || var.getOffset() >= 0) {
				return false;
			}

			boolean isThisParam =
				CreateStructureVariableAction.testForAutoParameterThis(var, rootFunction);
			Structure structDT =
				CreateStructureVariableAction.getStructureForExtending(var.getDataType());
			if (structDT != null) {
				componentMap.populateOriginalStructure(structDT);
			}

			fillOutStructureDef(var);
			pushIntoCalls();

			structDT = createStructure(structDT, var, rootFunction, isThisParam);
			populateStructure(structDT);

			DataType pointerDT = new PointerDataType(structDT);

			// Delay adding to the manager until full structure is accumulated
			pointerDT = currentProgram.getDataTypeManager()
					.addDataType(pointerDT, DataTypeConflictHandler.DEFAULT_HANDLER);
			commitVariable(var, pointerDT, isThisParam);
		}
		catch (Exception e) {
			Msg.showError(this, tool.getToolFrame(), "Auto Create Structure Failed",
				"Failed to create Structure variable", e);
		}
		finally {
			currentProgram.endTransaction(transaction, true);
		}

		return true;
	}

	/**
	 * Method to create a structure data type for a variable in the given function.
	 * Unlike the applyTo() action, this method will not modify the function, its variables,
	 * or any existing data-types. A new structure is always created.
	 * @param var a parameter, local variable, or global variable used in the given function
	 * @param function the function to process
	 * @return a filled-in structure or null if one could not be created
	 */
	public Structure processStructure(HighVariable var, Function function) {

		if (var == null || var.getSymbol() == null || var.getOffset() >= 0) {
			return null;
		}

		Structure structDT;

		try {
			fillOutStructureDef(var);
			pushIntoCalls();
			structDT = createStructure(null, var, function, false);
			populateStructure(structDT);
		}
		catch (Exception e) {
			return null;
		}

		return structDT;
	}

	/**
	 * Retrieve the component map that was generated when structure was created using decomiler info
	 * @return componentMap
	 */
	public NoisyStructureBuilder getComponentMap() {
		return componentMap;
	}

	/**
	 * Retrieve the offset/pcodeOp pairs that are used to store data into the variable
	 * the FillInStructureCmd was trying to create a structure on.
	 * @return the pcodeOps doing the storing to the associated variable
	 */
	public List<OffsetPcodeOpPair> getStorePcodeOps() {
		return storePcodeOps;
	}

	/**
	 * Retrieve the offset/pcodeOp pairs that are used to load data from the variable
	 * the FillInStructureCmd was trying to create a structure on.
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
			Iterator<Address> keyIter = keys.iterator();
			while (keyIter.hasNext()) {
				Address addr = keyIter.next();

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
	 * Retype the HighVariable to a given data-type to the database
	 * @param var is the decompiler variable to retype
	 * @param newDt is the data-type
	 * @param isThisParam is true if the variable is a 'this' pointer
	 */
	private void commitVariable(HighVariable var, DataType newDt, boolean isThisParam) {
		if (!isThisParam) {
			try {
				HighFunctionDBUtil.updateDBVariable(var.getSymbol(), null, newDt,
					SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
			catch (InvalidInputException e) {
				Msg.error(this,
					"Failed to re-type variable " + var.getName() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Compute the storage address associated with a particular Location
	 * @param location is the location being queried
	 * @param function is the function owning the location
	 * @return the corresponding storage address or null
	 */
	private Address computeStorageAddress(ProgramLocation location, Function function) {

		Address storageAddress = null;

		// make sure what we are over can be mapped to decompiler
		// param, local, etc...

		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			storageAddress = varLoc.getVariable().getVariableStorage().getMinAddress();
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
			storageAddress = funcPFL.getParameter().getVariableStorage().getMinAddress();
		}
		return storageAddress;
	}

	/**
	 * Decompile a function and return the resulting HighVariable associated with a storage address
	 * @param storageAddress the storage address of the variable
	 * @param function is the function
	 * @return the corresponding HighVariable
	 */
	private HighVariable computeHighVariable(Address storageAddress, Function function) {
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

			DecompileResults results = decompileFunction(function, decomplib);
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

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = tool.getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, currentProgram);
		}
		decomplib.setOptions(options);

		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");

		return decomplib;
	}

	public DecompileResults decompileFunction(Function f, DecompInterface decomplib) {
		DecompileResults decompRes;

		decompRes =
			decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);

		return decompRes;
	}

	/**
	 * Recover the structure associated with the given pointer variable, or if there is no structure,
	 * create it.  Resize the structure to be at least as large as the maxOffset seen so far.
	 * @param structDT is the structure data-type to fill in, or null if a new Structure should be created
	 * @param var is the given pointer variable
	 * @param f is the function
	 * @param isThisParam is true if the variable is a 'this' pointer
	 * @return the Structure object
	 */
	private Structure createStructure(Structure structDT, HighVariable var, Function f,
			boolean isThisParam) {

		if (structDT == null) {
			structDT = createNewStruct(var, (int) componentMap.getSize(), f, isThisParam);
		}
		else {
			// FIXME: How should an existing packed structure be handled? Growing and offset-based placement does not apply
			int len = structDT.isZeroLength() ? 0 : structDT.getLength();
			if (componentMap.getSize() > len) {
				structDT.growStructure((int) componentMap.getSize() - len);
			}
		}
		return structDT;
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
	 * Create a new structure of a given size. If the associated variable is a 'this' pointer,
	 * make sure there is a the structure is associated with the class namespace.
	 * @param var is the associated variable
	 * @param size is the desired structure size
	 * @param f is the function owning the variable
	 * @param isThisParam is true if the variable is a 'this' variable
	 * @return the new Structure
	 */
	private Structure createNewStruct(HighVariable var, int size, Function f, boolean isThisParam) {
		if (isThisParam) {
			Namespace rootNamespace = currentProgram.getGlobalNamespace();
			Namespace newNamespace = createUniqueClassName(rootNamespace);
			RenameLabelCmd command = new RenameLabelCmd(f.getEntryPoint(), f.getName(), f.getName(),
				rootNamespace, newNamespace, SourceType.USER_DEFINED);
			if (!command.applyTo(currentProgram)) {
				return null;
			}
			Structure structDT = VariableUtilities.findOrCreateClassStruct(f);
// FIXME: How should an existing packed structure be handled? Growing and offset-based placement does not apply
			int len = structDT.isZeroLength() ? 0 : structDT.getLength();
			if (len < size) {
				structDT.growStructure(size - len);
			}
			return structDT;
		}
		String structName = createUniqueStructName(var, DEFAULT_CATEGORY, DEFAULT_BASENAME);

		StructureDataType dt = new StructureDataType(new CategoryPath(DEFAULT_CATEGORY), structName,
			size, f.getProgram().getDataTypeManager());
		return dt;
	}

	private Namespace createUniqueClassName(Namespace rootNamespace) {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		String newClassBase = "AutoClass";
		String newClassName = "";
		for (int i = 1; i < 1000; ++i) {
			newClassName = newClassBase + Integer.toString(i);
			if (symbolTable.getSymbols(newClassName, rootNamespace).isEmpty()) {
				break;
			}
		}
		// Create the class
		GhidraClass newClass = null;
		try {
			newClass =
				symbolTable.createClass(rootNamespace, newClassName, SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException e) {
			// Shouldn't happen
			e.printStackTrace();
		}
		catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return newClass;
	}

	private String createUniqueStructName(HighVariable var, String category, String base) {
		return currentProgram.getDataTypeManager().getUniqueName(new CategoryPath(category), base);
	}

	private boolean sanityCheck(long offset) {
		if (offset < 0) {
			return false; // offsets shouldn't be negative
		}
		if (offset > 0x1000) {
			return false; // Arbitrary size cut-off to prevent creating huge structures
		}
		return true;
	}

	/**
	 * Get the data-type associated with a Varnode.  If the Varnode is produce by a CAST p-code
	 * op, take the most specific data-type between what it was cast from and cast to.
	 * @param vn is the Varnode to get the data-type for
	 * @return the data-type
	 */
	public static DataType getDataTypeTraceBackward(Varnode vn) {
		DataType res = vn.getHigh().getDataType();
		PcodeOp op = vn.getDef();
		if (op != null && op.getOpcode() == PcodeOp.CAST) {
			Varnode otherVn = op.getInput(0);
			res = MetaDataType.getMostSpecificDataType(res, otherVn.getHigh().getDataType());
		}
		return res;
	}

	/**
	 * Get the data-type associated with a Varnode.  If the Varnode is input to a CAST p-code
	 * op, take the most specific data-type between what it was cast from and cast to.
	 * @param vn is the Varnode to get the data-type for
	 * @return the data-type
	 */
	public static DataType getDataTypeTraceForward(Varnode vn) {
		DataType res = vn.getHigh().getDataType();
		PcodeOp op = vn.getLoneDescend();
		if (op != null && op.getOpcode() == PcodeOp.CAST) {
			Varnode otherVn = op.getOutput();
			res = MetaDataType.getMostSpecificDataType(res, otherVn.getHigh().getDataType());
		}
		return res;
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
						if (sanityCheck(newOff)) { // should this offset create a location in the structure?
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
						if (sanityCheck(newOff)) { // should this offset create a location in the structure?
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
						if (sanityCheck(subOff)) { // should this offset create a location in the structure?
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
						outDt = getDataTypeTraceForward(output);
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
						outDt = getDataTypeTraceBackward(inputs[2]);
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
							outDt = getDataTypeTraceBackward(currentRef.varnode);
							componentMap.addReference(currentRef.offset, outDt);
						}
						break;
					case PcodeOp.CALLIND:
						outDt = getDataTypeTraceBackward(currentRef.varnode);
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
