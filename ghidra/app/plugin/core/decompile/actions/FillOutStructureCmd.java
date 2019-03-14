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
 * Automatically creates a structure definition based on the references seen to the structure
 * To use this, place the cursor on a function parameter for example func(int *this),
 * (for a C++ this call function)
 * This script will automatically create a structure definition for the pointed at structure
 * and fill it out based on the references found by the decompiler.
 *
 * If the parameter is already a structure pointer, any new references found will be added
 * to the structure, even if the structure must grow.
 *
 * Eventually this WILL be put into a global type analyzer, but for now it is most useful.
 *
 * This assumes good flow, that switch statements are good.
 *
 * This CAN be used in the decompiler by assigning a Binding a Keyboard key to it, then
 * placing the cursor on the variable in the decompiler that is a structure pointer (even if it
 * isn't one now, and then pressing the Quick key.
 *
 */
public class FillOutStructureCmd extends BackgroundCommand {
	private static final String DEFAULT_BASENAME = "astruct";
	private static final String DEFAULT_CATEGORY = "/auto_structs";

	private ArrayList<Varnode> varnodeTodo = new ArrayList<>();
	private ArrayList<Long> offsetTodo = new ArrayList<>();
	private HashSet<Varnode> doneList = new HashSet<>();
	private boolean isIntegerBase = false;
	private long maxOffset = 0;

	private HashMap<Long, DataType> offsetToDataTypeMap = new HashMap<>();
	private HashMap<Address, Integer> addressToCallInputMap = new HashMap<>();

	private Program currentProgram;
	private ProgramLocation currentLocation;
	private Function rootFunction;
	private TaskMonitor monitor;
	private PluginTool tool;

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
		this.currentLocation = location;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		this.monitor = monitor;

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
				var = computeVariableLocation(currentProgram, currentLocation, rootFunction);
			}
			else {

				// get the Varnode under the cursor
				DecompilerLocation dloc = (DecompilerLocation) currentLocation;
				ClangToken token = dloc.getToken();
				if (token == null) {
					return false;
				}

				fixupParams(dloc.getDecompile(), rootFunction);
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

			if (var == null) {
				return false;
			}

			boolean isThisParam =
				CreateStructureVariableAction.testForAutoParameterThis(var, rootFunction);

			fillOutStructureDef(var);

			DataType struct = createStructure(var, rootFunction, isThisParam);

			pushIntoCalls(struct);
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

	private void pushIntoCalls(DataType struct) {
		AddressSet doneSet = new AddressSet();

		while (addressToCallInputMap.size() > 0) {
			HashMap<Address, Integer> savedList = addressToCallInputMap;
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
				int paramIndex = savedList.get(addr);

				// println("call parm:  " + func.getName() + " - " + paramIndex);
				boolean didSetParam = setParam(func, struct, paramIndex);
				if (didSetParam) {
					Parameter parameter = func.getParameter(paramIndex);
					boolean subIsThisParam =
						parameter.getAutoParameterType() == AutoParameterType.THIS;
					VariableLocation loc = new VariableLocation(func.getProgram(), parameter, 0, 0);
					HighVariable paramHighVar = computeVariableLocation(currentProgram, loc, func);
					fillOutStructureDef(paramHighVar);

					struct = createStructure(paramHighVar, func, subIsThisParam);
				}
			}
		}
	}

	private boolean setParam(Function func, DataType dt, int paramIndex) {
		if (func == null || func.hasVarArgs()) {
			return false;
		}

		DecompInterface decomplib = setUpDecompiler(currentProgram);

		try {
			if (!decomplib.openProgram(currentProgram)) {
				return false;
			}

			DecompileResults results = decompileFunction(func, decomplib);
			HighFunction hf = results.getHighFunction();
			if (hf == null) {
				return false;
			}

			fixupParams(results, func);

			// make sure prototype of called function didn't change!
			PrototypeModel convention = func.getCallingConvention();
			// if (initialConvention == null && convention != null) {
			// return true;
			// }
			if (convention == null) {
				convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
			}
			// if (initialConvention != null &&
			// !convention.getName().equals(initialConvention.getName())) {
			// return true;
			// }

			Parameter param = func.getParameter(paramIndex);
			if (param != null && param.getDataType() instanceof Pointer) {
				Pointer pdt = (Pointer) param.getDataType();
				DataType ldt = pdt.getDataType();
				if (!(ldt instanceof Undefined) && !(ldt instanceof IntegerDataType)) {
					return false;
				}
			}
			else if (param != null) {
				DataType ldt = param.getDataType();
				if (!(ldt instanceof Undefined) && !(ldt instanceof IntegerDataType)) {
					return false;
				}
			}

			if (param == null) {
				if (convention == null) {
					return false;
				}
				Parameter[] parameters = func.getParameters();
				VariableStorage storage =
					convention.getArgLocation(parameters.length, parameters, dt, currentProgram);
				try {
					param = new ParameterImpl(null, dt, storage, currentProgram);
					param = func.addParameter(param, SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Failed to create structure parameter at " +
						func.getEntryPoint() + ": " + e.getMessage());
					return false;
				}
			}
			else {
				// TODO: may need to allocate new storage
				param.setDataType(dt, SourceType.USER_DEFINED);
			}
			currentProgram.getBookmarkManager().setBookmark(func.getEntryPoint(), BookmarkType.NOTE,
				this.getClass().getName(), "Created char* parameter");

			return true;

		}
		catch (InvalidInputException e) {
			Msg.error(this, "Failed to assign structure parameter at " + func.getEntryPoint() +
				": " + e.getMessage());
			return false;
		}
		finally {
			decomplib.dispose();
		}
	}

	private void fixupParams(DecompileResults decompResults, Function f)
			throws InvalidInputException {
		// must make number of parameters agree with function, because will be
		// storing off a structure ptr
		HighFunction hf = decompResults.getHighFunction();
		if (hf == null) {
			return;
		}

		// must make number of parameters agree with function, because will be storing off a structure ptr
		LocalSymbolMap vmap = decompResults.getHighFunction().getLocalSymbolMap();
		int numParams = vmap.getNumParams();
		if (f.getParameterCount() != numParams) {
			try {
				HighFunctionDBUtil.commitParamsToDatabase(decompResults.getHighFunction(), true,
					SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
		}
	}

	private HighVariable computeVariableLocation(Program program, ProgramLocation location,
			Function function) {

		HighVariable highVar = null;
		Address storageAddress = null;

		// make sure what we are over can be mapped to decompiler
		// param, local, etc...

		Address addr = location.getAddress();
		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			storageAddress = varLoc.getVariable().getVariableStorage().getMinAddress();
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
			storageAddress = funcPFL.getParameter().getVariableStorage().getMinAddress();
		}
		else {
			return findFunctionReturn(location.getProgram(), location.getAddress(), function);
		}

		if (storageAddress == null) {
			return null;
		}

		// setup the decompiler
		DecompInterface decomplib = setUpDecompiler(program);

		// call it to get results
		try {
			if (!decomplib.openProgram(program)) {
				return null;
			}

			if (addr == null) {
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
				sym = highFunc.getLocalSymbolMap().findLocal(storageAddress,
					function.getEntryPoint().subtractWrap(1L));
			}
			if (sym == null) {
				sym = highFunc.getLocalSymbolMap().findLocal(storageAddress, null);
			}
			if (sym == null) {
				sym = highFunc.getLocalSymbolMap().findLocal(storageAddress,
					function.getEntryPoint());
			}
			if (sym == null) {
				return null;
			}

			highVar = sym.getHighVariable();
			if (highVar != null) {
				try {
					fixupParams(results, function);
				}
				catch (InvalidInputException e) {
					Msg.error(this, e.getMessage());
					return null;
				}
			}

		}
		finally {
			decomplib.dispose();
		}

		// figure out how to map what the user is over into decompiler variable

		return highVar;
	}

	/**
	 * Assume we are on a function that is being called, try to find the output
	 * varnode here from the decompiler.
	 *
	 * @param program
	 * @param address
	 * @param function
	 * @return
	 */
	private HighVariable findFunctionReturn(Program program, Address address, Function function) {
		if (program == null) {
			program = currentProgram;
		}

		// setup the decompiler
		DecompInterface decomplib = setUpDecompiler(program);

		HighVariable varAddr = null;

		// call it to get results
		try {
			if (!decomplib.openProgram(program)) {
				// println("Decompile Error: " + decomplib.getLastMessage());
				return null;
			}

			if (address == null) {
				return null;
			}

			DecompileResults results = decompileFunction(function, decomplib);
			HighFunction hfunc = results.getHighFunction();
			if (hfunc == null) {
				return null;
			}

			Iterator<PcodeOpAST> ops = hfunc.getPcodeOps(address);
			while (ops.hasNext()) {
				PcodeOpAST op = ops.next();
				if (op.getOpcode() == PcodeOp.CALL) {
					Varnode vnode = op.getOutput();
					varAddr = vnode.getHigh();
					if (varAddr instanceof HighOther) {
						Iterator<PcodeOp> descendants = vnode.getDescendants();
						while (descendants.hasNext()) {
							PcodeOp desc = descendants.next();
							if (desc.getOpcode() == PcodeOp.CAST) {
								vnode = desc.getOutput();
								varAddr = vnode.getHigh();
								break;
							}
						}
					}
					break;
				}
			}
		}
		finally {
			decomplib.dispose();
		}
		return varAddr;
	}

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decomplib = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = tool.getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
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

	private DataType createStructure(HighVariable var, Function f, boolean isThisParam) {

		Structure structDT = null;
		int ptrDepth = 0;

		DataType varDT = var.getDataType();
		if (varDT instanceof Structure) {
			structDT = (StructureDataType) varDT;
		}
		else if (varDT instanceof Pointer) {
			DataType dt = ((Pointer) varDT).getDataType();
			ptrDepth = 1;
			while (dt instanceof Pointer) {
				ptrDepth++;
				dt = ((Pointer) dt).getDataType();
			}
			if (dt instanceof Structure) {
				structDT = (Structure) dt;
			}
		}

		if (structDT == null) {
			structDT = createNewStruct(var, (int) maxOffset, f, isThisParam);
		}
		else {
			int len;
			if (structDT.isNotYetDefined()) {
				len = 0;
			}
			else {
				len = structDT.getLength();
			}
			if (maxOffset > len) {
				structDT.growStructure((int) maxOffset - len);
			}
		}

		Iterator<Long> iterator = offsetToDataTypeMap.keySet().iterator();
		while (iterator.hasNext()) {
			Long key = iterator.next();
			DataType valDT = offsetToDataTypeMap.get(key);
			if (key.intValue() < 0) {
				// println("    BAD OFFSET : " + key.intValue());
				continue;
			}

			// TODO: need to do data type conflict resolution
			if (structDT.getLength() < (key.intValue() + valDT.getLength())) {
				continue;
			}

			try {
				DataTypeComponent existing = structDT.getDataTypeAt(key.intValue());
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

		// TODO: need to create a pointer, or just lay down the structure,
		// depending on where structure is located
		DataType newDt = structDT;
		if (varDT instanceof Pointer || isIntegerBase) {
			DataType pdt = new PointerDataType(structDT);
			for (int i = 1; i < ptrDepth; i++) {
				pdt = new PointerDataType(pdt);
			}
			pdt = currentProgram.getDataTypeManager().addDataType(pdt,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			newDt = pdt;
		}
		if (!isThisParam) {
			try {
				HighFunctionDBUtil.updateDBVariable(var, null, newDt, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
			catch (InvalidInputException e) {
				Msg.error(this,
					"Failed to re-type variable " + var.getName() + ": " + e.getMessage());
			}
		}
		return newDt;
	}

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
			int len;
			if (structDT.isNotYetDefined()) {
				len = 0; // getLength reports as at least size 1
			}
			else {
				len = structDT.getLength();
			}
			if (len < size) {
				structDT.growStructure(size - len);
			}
			return structDT;
		}
		String structName = createUniqueStructName(var, DEFAULT_CATEGORY, DEFAULT_BASENAME);

		StructureDataType dt =
			new StructureDataType(new CategoryPath(DEFAULT_CATEGORY), structName, size);
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

	private void fillOutStructureDef(HighVariable var) {
		Varnode startVN = var.getRepresentative();

		if (!(var.getDataType() instanceof Pointer)) {
			isIntegerBase = true;
		}

		// put Vnode on Todo list
		varnodeTodo.add(startVN);

		// put Vnode ofset on offset Todo list
		offsetTodo.add(Long.valueOf(0));

		// while Todo list not empty
		while (!varnodeTodo.isEmpty()) {
			Varnode doVn = varnodeTodo.remove(0);
			long offset = offsetTodo.remove(0);
			if (doVn == null) {
				continue;
			}

			Varnode[] instances = doVn.getHigh().getInstances();
			// println("");
			for (Varnode iVn : instances) {
				Iterator<PcodeOp> descendants = iVn.getDescendants();
				while (descendants.hasNext()) {
					PcodeOp pcodeOp = descendants.next();
					Varnode output = pcodeOp.getOutput();
					Varnode[] inputs = pcodeOp.getInputs();
					// println("off=" + offset + "     " + pcodeOp.getSeqnum().getTarget().toString() + " : "
					//		+ pcodeOp.toString());

					DataType outDt, inDt, subDt;

					long newOff;
					switch (pcodeOp.getOpcode()) {
						case PcodeOp.INT_SUB:
						case PcodeOp.INT_ADD:
							if (!inputs[1].isConstant()) {
								break;
							}
							outDt = output.getHigh().getDataType();
							// println("        type = " + outDt.getName());
							long value = getSigned(inputs[1]);
							newOff = offset +
								((pcodeOp.getOpcode() == PcodeOp.INT_ADD) ? value : (-value));
							subDt = outDt;
							if (outDt instanceof Pointer) {
								subDt = ((Pointer) outDt).getDataType();
							}
							if (sanityCheck(newOff)) { // should this offset create a location in the structure?
								// if (subDt != null) {
								// structDefs.put(Long.valueOf(offset), subDt);
								// }
								putOnList(output, newOff);
								maxOffset = computeMax(maxOffset, newOff, 0);
							}
							break;
						case PcodeOp.PTRADD:
							if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
								break;
							}
							outDt = output.getHigh().getDataType();
							// println("        type = " + outDt.getName());
							newOff = offset + getSigned(inputs[1]) * inputs[2].getOffset();
							subDt = outDt;
							if (outDt instanceof Pointer) {
								subDt = ((Pointer) outDt).getDataType();
							}
							if (sanityCheck(newOff)) { // should this offset create a location in the structure?
								// if (subDt != null) {
								// structDefs.put(Long.valueOf(offset), subDt);
								// }
								putOnList(output, newOff);
								maxOffset = computeMax(maxOffset, newOff, 0);
							}
							break;
						case PcodeOp.PTRSUB:
							if (!inputs[1].isConstant()) {
								break;
							}
							inDt = inputs[0].getHigh().getDataType();
							subDt = output.getHigh().getDataType();
							// println("        type = " + subDt.getName());
							long subOff = offset + getSigned(inputs[1]);
							outDt = subDt;
							if (subDt instanceof Pointer) {
								outDt = ((Pointer) subDt).getDataType();
							}
							if (sanityCheck(subOff)) { // should this offset create a location in the structure?
								// if (outDt != null) {
								// structDefs.put(Long.valueOf(offset), outDt);
								// }
								putOnList(output, subOff);
								maxOffset = computeMax(maxOffset, subOff, 0);
							}
							break;
						case PcodeOp.SEGMENTOP:
							// treat segment op as if it were a cast to complete the value
							//   The segment adds in some unknown base value.
							// get output and add to the Varnode Todo list
							putOnList(output, offset);
							break;

						case PcodeOp.LOAD:
							// create a location in the struct
							// println("   load -> " + offset);
							outDt = output.getHigh().getDataType();
							inDt = inputs[1].getHigh().getDataType();
							if (outDt != null) {
								offsetToDataTypeMap.put(Long.valueOf(offset), outDt);
							}
							maxOffset = computeMax(maxOffset, offset, output.getSize());
							break;
						case PcodeOp.STORE:
							// create a location in the struct
							// println("   store -> " + offset);
							inDt = inputs[1].getHigh().getDataType();
							outDt = inDt;
							if (inDt instanceof Pointer) {
								outDt = ((Pointer) inDt).getDataType();
							}
							int outLen = 1; // Storing at least one byte
							if (outDt != null) {
								offsetToDataTypeMap.put(Long.valueOf(offset), outDt);
								outLen = outDt.getLength();
							}

							maxOffset = computeMax(maxOffset, offset, outLen);
							// println("        type = " + inDt.getName());
							break;

						case PcodeOp.CAST:
							// get output and add to the Varnode Todo list
							putOnList(output, offset);
							break;
						case PcodeOp.MULTIEQUAL:
							putOnList(output, offset);
							break;
						case PcodeOp.COPY:
							putOnList(output, offset);
							break;
						case PcodeOp.CALL:
							// find it as an input
							Varnode[] callInputs = pcodeOp.getInputs();
							for (int j = 0; j < callInputs.length; j++) {
								if (callInputs[j].equals(iVn)) {
									putOnCallParamList(callInputs[0].getAddress(), j - 1);
								}
							}
							break;
					}

				}
			}
		}
	}

	private void putOnCallParamList(Address address, int j) {
		addressToCallInputMap.put(address, j);
	}

	private long computeMax(long max, long newOff, int length) {
		if (max < (newOff + length)) {
			max = newOff + length;
		}
		return max;
	}

	private long getSigned(Varnode varnode) {
		long mask = 0x80L << ((varnode.getSize() - 1) * 8);
		long value = varnode.getOffset();
		if ((value & mask) != 0) {
			value |= (0xffffffffffffffffL << ((varnode.getSize() - 1) * 8));
		}
		return value;
	}

	private void putOnList(Varnode output, long offset) {
		if (doneList.contains(output)) {
			return;
		}
		varnodeTodo.add(output);
		offsetTodo.add(offset);
		doneList.add(output);
		// println(" off=" + offset);
	}
}
