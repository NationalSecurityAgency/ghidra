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
// Given a variable in the decompiler, walk backward through function calls to find any constants
//   that find their way directly into the variable.  Very useful for getting a list of all the
//   constants passed to a parameter, or to a parameter at a given location in the program.
//
//   The guts of this script past the main could be used to analyze
//   constants passed to any function on any processor.
//   It is not restricted to windows.
//
//@category Search

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.*;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class ShowConstantUse extends GhidraScript {
	private DecompInterface decomplib;
	DecompileResults lastResults = null;
	TableChooserDialog tableDialog;

	@Override
	public void run() throws Exception {
		TableChooserExecutor executor = null;
		// executor = createTableExecutor();

		tableDialog = createTableChooserDialog("Constant Values", executor);
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Searching...");

		try {
			// get the decompiler context
			// setup the decompiler
			decomplib = setUpDecompiler(currentProgram);

			// find out what we are on (param, variable, etc...
			@SuppressWarnings("unused")
			HashMap<Address, Long> constLocs;

			Varnode var = getVarnodeLocation();

			if (var != null && !var.isConstant()) {
				constLocs = backtrackToConstant(var, tableDialog);
			}
			else {
				// if couldn't find a varnode location, then must be on a
				// function parameter with no body
				// just backtrack the parameter from the function parameter
				if (currentLocation instanceof FunctionParameterFieldLocation) {
					FunctionParameterFieldLocation funcPFL =
						(FunctionParameterFieldLocation) currentLocation;
					Function f = funcPFL.getParameter().getFunction();
					int paramIndex = funcPFL.getParameter().getOrdinal();
					constLocs = backtrackParamToConstant(f, paramIndex, tableDialog);
				}
				else if (currentLocation instanceof VariableNameFieldLocation) {
					VariableNameFieldLocation varNFL = (VariableNameFieldLocation) currentLocation;
					Variable funcvar = varNFL.getVariable();
					Function f = funcvar.getFunction();
					if (funcvar instanceof Parameter) {
						int paramIndex = ((Parameter) funcvar).getOrdinal();
						constLocs = backtrackParamToConstant(f, paramIndex, tableDialog);
					}
				}
				else if (currentLocation instanceof DecompilerLocation) {
					// must be inside the decompiler, locate the parameter we are on within a function.
					DecompilerLocation decL = (DecompilerLocation) currentLocation;
					ClangToken token = decL.getToken();
					if (token instanceof ClangVariableToken) {
						ClangVariableToken clangVar = (ClangVariableToken) token;
						ClangNode parent = token.Parent();
						if (parent instanceof ClangStatement) {
							ClangStatement clangStmt = (ClangStatement) parent;
							PcodeOp pcodeOp = clangStmt.getPcodeOp();
							if (pcodeOp.getOpcode() == PcodeOp.CALL) {
								Varnode input = pcodeOp.getInput(0);
								if (input.isAddress()) {
									Address faddr = input.getAddress();
									Function f = getReferencedFunction(faddr);
									int paramIndex = 0;
									for (int i = 0; i < clangStmt.numChildren(); i++) {
										ClangNode child = clangStmt.Child(i);
										if (child.equals(clangVar)) {
											constLocs = backtrackParamToConstant(f, paramIndex,
												tableDialog);
											break;
										}
										if (child instanceof ClangVariableToken) {
											paramIndex++;
										}
									}
								}
							}
						}
					}
				}
				else {
					tableDialog.setMessage("****   please put the cursor on a variable!   ****");
				}
			}
		}
		finally {
			decomplib.dispose();
		}
		tableDialog.setMessage("Finished!");
	}

	private Function getReferencedFunction(Address functionAddress) {
		Function f = currentProgram.getFunctionManager().getFunctionAt(functionAddress);
		// couldn't find the function, see if there is an external ref there.
		if (f == null) {
			Reference[] referencesFrom =
				currentProgram.getReferenceManager().getReferencesFrom(functionAddress);
			for (Reference reference : referencesFrom) {
				if (reference.isExternalReference()) {
					functionAddress = reference.getToAddress();
					f = currentProgram.getFunctionManager().getFunctionAt(functionAddress);
					if (f != null) {
						break;
					}
				}
			}
		}
		return f;
	}

	/**
	 * Builds the configurable columns for the TableDialog. More columns could be added.
	 * 
	 * @param tableChooserDialog the dialog 
	 */
	private void configureTableColumns(TableChooserDialog tableChooserDialog) {
		// First column added is the Constant value that is found.
		// Note the special compare method that must compare the constant
		// values not as a default string rendering, but by actual value.
		StringColumnDisplay constColumn = new StringColumnDisplay() {
			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				ConstUseLocation e1 = (ConstUseLocation) o1;
				ConstUseLocation e2 = (ConstUseLocation) o2;
				Long v1 = e1.getConstValue();
				Long v2 = e2.getConstValue();
				if (SystemUtilities.isEqual(v1, v2)) {
					return 0;
				}
				if (v1 == null) {
					return -1;
				}
				if (v2 == null) {
					return 1;
				}

				return (int) (v1 - v2);
			}

			@Override
			public String getColumnName() {
				return "Constant Value";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ConstUseLocation entry = (ConstUseLocation) rowObject;
				Long val = entry.getConstValue();
				if (val == null) {
					return "";
				}
				return Long.toHexString(val);
			}
		};

		// Displays a preview of anything defined at an address if the constant
		// discovered in the backtrack search could be treated as an address
		//
		StringColumnDisplay addrPreviewColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Addr Preview";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ConstUseLocation entry = (ConstUseLocation) rowObject;
				Long val = entry.getConstValue();
				if (val == null) {
					return "";
				}
				Address addr = entry.getAddress();
				if (addr == null) {
					return "";
				}
				Address potAddr = addr.getNewAddress(val);
				if (addr.getAddressSpace().isOverlaySpace()) {
					potAddr = addr.getAddressSpace().getOverlayAddress(potAddr);
				}
				if (!currentProgram.getMemory().contains(potAddr)) {
					return "";
				}
				Listing listing = currentProgram.getListing();
				Data data = listing.getDefinedDataAt(potAddr);
				if (data != null) {
					return data.toString();
				}
				Function f = currentProgram.getFunctionManager().getFunctionAt(potAddr);
				if (f != null) {
					return f.getPrototypeString(false, false);
				}
				return "";
			}
		};

		// column to display the name of the function containing the address
		// where a
		// constant is found to be used.
		StringColumnDisplay funcColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Func Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ConstUseLocation entry = (ConstUseLocation) rowObject;
				Function func = entry.getProgram()
						.getFunctionManager()
						.getFunctionContaining(
							entry.getAddress());
				if (func == null) {
					return "";
				}
				return func.getName();
			}
		};

		// column to display the note at the address where a
		// this is usually an error condition
		StringColumnDisplay noteColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Note";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ConstUseLocation entry = (ConstUseLocation) rowObject;
				String note = entry.getNote();
				if (note == null) {
					return "";
				}
				return note;
			}
		};

		tableChooserDialog.addCustomColumn(constColumn);
		tableChooserDialog.addCustomColumn(addrPreviewColumn);
		tableChooserDialog.addCustomColumn(funcColumn);
		tableChooserDialog.addCustomColumn(noteColumn);
	}

	/**
	 * Sample execution task Execution class called whenever the execute button
	 * in the table is called. NOTE: the execute button is not setup, so this is
	 * just and example
	 * 
	 * Useful if you are back tracking constants for malloc or calloc Runs
	 * another script that will create a structure on the return variable of
	 * calloc/malloc. It pulls a little trick when calling the CreateStructure
	 * script by creating an artificial ScriptState. This is a useful technique
	 * for other scripts as well.
	 * 
	 * @return the executor
	 */
	@SuppressWarnings("unused")
	private TableChooserExecutor createTableExecutor() {

		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Create Structure";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				ConstUseLocation constLoc = (ConstUseLocation) rowObject;
				println("Follow Structure : " + rowObject.getAddress());

				Program cp = constLoc.getProgram();
				Address entry = constLoc.getAddress();

				println("Create Structure at " + entry);

				runScript("CreateStructure.java", cp, entry);
				return false; // don't remove row from display table
			}

			public void runScript(String name, Program prog, Address loc) {
				GhidraState scriptState = new GhidraState(state.getTool(), state.getProject(), prog,
					new ProgramLocation(prog, loc), null, null);
				try {
					ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(name);
					if (scriptSource != null) {
						GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);
						GhidraScript script = provider.getScriptInstance(scriptSource, writer);
						script.execute(scriptState, monitor, writer);
						return;
					}
				}
				catch (Exception exc) {
					Msg.error(this, "Exception running script", exc);
				}
				throw new IllegalArgumentException("Script does not exist: " + name);
			}
		};
		return executor;
	}

	// Object that gathers the constant used locations within the program
	//
	class ConstUseLocation implements AddressableRowObject {
		private Program program;
		private Address addr;
		private Long constVal;
		private String note;

		ConstUseLocation(Program prog, Address addr, Long constVal, String note) {
			this.addr = addr;
			this.constVal = constVal;
			this.program = prog;
			this.note = note;
		}

		public Program getProgram() {
			return program;
		}

		@Override
		public Address getAddress() {
			return addr;
		}

		public Long getConstValue() {
			return constVal;
		}

		public String getNote() {
			return note;
		}
	}

	/**
	 * Try to locate the Varnode that represents the variable in the listing or
	 * decompiler. In the decompiler this could be a local/parameter at any
	 * point in the decompiler. In the listing, it must be a parameter variable.
	 * 
	 * @return the varnode
	 */
	private Varnode getVarnodeLocation() {
		Varnode var = null;

		if (currentLocation instanceof DecompilerLocation) {
			DecompilerLocation dloc;

			// get the Varnode under the cursor
			dloc = (DecompilerLocation) currentLocation;
			ClangToken tokenAtCursor = dloc.getToken();
			var = DecompilerUtils.getVarnodeRef(tokenAtCursor);
			// fixupParams(dloc.getDecompile(), currentLocation.getAddress());
			if (tokenAtCursor == null) {
				println("****   please put the cursor on a variable in the decompiler!");
				return null;
			}
			lastResults = dloc.getDecompile();
		}
		else {
			// if we don't have one, make one, and map variable to a varnode
			HighSymbol highVar = computeVariableLocation(currentProgram, currentLocation);
			if (highVar != null) {
				var = highVar.getHighVariable().getRepresentative();
			}
			else {
				return null;
			}
		}
		return var;
	}

	private void addConstants(TableChooserDialog tableChooserDialog,
			HashMap<Address, Long> constLocs) {
		Set<Address> keys;
		keys = constLocs.keySet();
		Address[] keyArray = keys.toArray(new Address[0]);
		Arrays.sort(keyArray);
		for (Address loc : keyArray) {
			Long constant = constLocs.get(loc);
			tableChooserDialog.add(new ConstUseLocation(currentProgram, loc, constant, null));
		}
	}

	private void addConstantProblem(TableChooserDialog tableChooserDialog, Address refAddr,
			String problem) {
		tableChooserDialog.add(new ConstUseLocation(currentProgram, refAddr, null, problem));
		println(problem);
	}

	private HighSymbol computeVariableLocation(Program currProgram, ProgramLocation location) {
		HighSymbol highVar = null;
		Address storageAddress = null;

		// make sure what we are over can be mapped to decompiler
		// param, local, etc...

		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			storageAddress = varLoc.getVariable().getMinAddress();
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
			storageAddress = funcPFL.getParameter().getMinAddress();
		}
		else if (location instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) location;
			int opindex = opLoc.getOperandIndex();
			if (opindex >= 0) {
				Instruction instr = currProgram.getListing().getInstructionAt(opLoc.getAddress());
				if (instr != null) {
					Register reg = instr.getRegister(opindex);
					if (reg != null) {
						storageAddress = reg.getAddress();
					}
				}
			}
		}

		if (storageAddress == null) {
			return null;
		}

		Address addr = currentLocation.getAddress();
		if (addr == null) {
			return null;
		}

		Function f = currProgram.getFunctionManager().getFunctionContaining(addr);
		if (f == null) {
			return null;
		}

		DecompileResults results = decompileFunction(f, decomplib);

		HighFunction hf = results.getHighFunction();
		if (hf == null) {
			return null;
		}

		// try to map the variable
		highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint().subtractWrap(1L));
		if (highVar == null) {
			highVar = hf.getMappedSymbol(storageAddress, null);
		}
		if (highVar == null) {
			highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint());
		}

		if (highVar != null) {
			// fixupParams(results, location.getAddress());
		}

		return highVar;
	}

	// These contains fields that are part of the back-tracking process if a
	// variable is traced
	// to the parameter of function, this is an entry for that location
	public class FunctionParamUse {
		String name;
		Address addr;
		Integer paramIndex;
		Varnode representative;
		ArrayList<PcodeOp> defUseList;

		public FunctionParamUse(String name, Address addr, int i, Varnode varnode,
				ArrayList<PcodeOp> defUseList) {
			this.name = name;
			this.addr = addr;
			this.paramIndex = i;
			this.defUseList = defUseList;
			this.representative = varnode;
		}

		public String getName() {
			return name;
		}

		public Address getAddress() {
			return addr;
		}

		public int getParamIndex() {
			return paramIndex;
		}

		public Varnode getRepresentative() {
			return representative;
		}

		public ArrayList<PcodeOp> getDefUseList() {
			return defUseList;
		}
	}

	/**
	 * Backtrack to a constant given a varnode within a decompiled function This
	 * isn't useful for functions that can't be decompiled
	 * 
	 * @param var
	 *            varnode that represents a variable in a decompilation
	 * @param tableChooserDialog
	 *            - accumulate entries. Don't like passing it, but this way the
	 *            user gets immediate feedback as locations are found
	 * @return a map of Addresses->constants (constants could be NULL)
	 * @throws CancelledException if cancelled
	 */
	private HashMap<Address, Long> backtrackToConstant(Varnode var,
			TableChooserDialog tableChooserDialog) throws CancelledException {

		HashMap<Address, Long> constUse = new HashMap<Address, Long>();

		if (!decomplib.openProgram(currentProgram)) {
			println("Decompile Error: " + decomplib.getLastMessage());
			return constUse;
		}

		// follow varnode back to any constants, accumulating back to function
		// param
		ArrayList<FunctionParamUse> funcList = new ArrayList<FunctionParamUse>();

		ArrayList<PcodeOp> defUseList = new ArrayList<PcodeOp>();
		followToParam(constUse, defUseList, lastResults.getHighFunction(), var, funcList, null);

		addConstants(tableChooserDialog, constUse);

		return followFunctionParamToConstant(funcList, constUse, tableChooserDialog);
	}

	/**
	 * Backtrack to a constant given a start position of a parameter of a given
	 * function Useful if you want to start from a function paramter.
	 * 
	 * @param f function to start in
	 * @param paramIndex parameter index to backtrack from
	 * @param tableChooserDialog accumulate entries. Don't like passing it, but this way the
	 *         user gets immediate feedback as locations are found
	 * @return a map of Addresses to constants (constants could be NULL)
	 * @throws CancelledException if cancelled
	 */
	private HashMap<Address, Long> backtrackParamToConstant(Function f, int paramIndex,
			TableChooserDialog tableChooserDialog) throws CancelledException {
		HashMap<Address, Long> constUse = new HashMap<Address, Long>();

		ArrayList<FunctionParamUse> funcList = new ArrayList<FunctionParamUse>();

		if (f == null) {
			return constUse;
		}
		Varnode pvnode = null;
		Parameter parm = f.getParameter(paramIndex);
		if (parm == null) {
			this.popup(
				"Please put the cursor on a function parameter variable\nIf the function has not had it's parameters identified\nplease do so and try again");
			return constUse;
		}

		// TODO: Parameter storage could consist of more than one varnode
		pvnode = parm.getFirstStorageVarnode();

		if (pvnode == null) {
			return constUse;
		}
		funcList.add(new FunctionParamUse(f.getName(), f.getEntryPoint(), paramIndex, pvnode,
			new ArrayList<PcodeOp>()));

		addConstants(tableChooserDialog, constUse);

		return followFunctionParamToConstant(funcList, constUse, tableChooserDialog);
	}

	private HashMap<Address, Long> followFunctionParamToConstant(
			ArrayList<FunctionParamUse> funcList, HashMap<Address, Long> constUse,
			TableChooserDialog tableChooserDialog) throws CancelledException {

		// any routines we bumped into, process back up the chain
		HashSet<Address> doneRoutines = new HashSet<Address>();
		while (funcList.size() > 0) {
			// get the next function the variable has been traced back to
			FunctionParamUse funcVarUse = funcList.remove(0);
			Address addr = funcVarUse.getAddress();
			int paramIndex = funcVarUse.getParamIndex();
			ArrayList<PcodeOp> defUseList = funcVarUse.getDefUseList();

			// will do this at another time.
			if (doneRoutines.contains(addr)) {
				continue;
			}
			doneRoutines.add(addr);

			// find all functions referring to that place
			ReferenceIterator referencesTo =
				currentProgram.getReferenceManager().getReferencesTo(addr);
			for (Reference reference : referencesTo) {
				monitor.checkCanceled();

				// get function containing.
				Address refAddr = reference.getFromAddress();
				if (refAddr.getAddressSpace().getType() == AddressSpace.TYPE_NONE ||
					refAddr.isExternalAddress()) {
					continue;
				}

				Function refFunc =
					currentProgram.getFunctionManager().getFunctionContaining(refAddr);

				HashMap<Address, Long> localConstUse = new HashMap<Address, Long>();

				if (refFunc == null) {
					localConstUse.put(refAddr, null);
					String problem = "*** No function at " + refAddr +
						".\nCould not analyze constant use past this undefined function!";
					addConstantProblem(tableChooserDialog, refAddr, problem);
					refFunc = UndefinedFunction.findFunction(currentProgram, refAddr, monitor);
				}

				if (refFunc != null) {
					// decompile function
					// look for call to this function
					// display call
					@SuppressWarnings("unchecked")
					ArrayList<PcodeOp> localDefUseList = (ArrayList<PcodeOp>) defUseList.clone();

					this.monitor.setMessage("Analyzing : " + refFunc.getName() + " for refs to " +
						addr + ":" + paramIndex);

					analyzeFunction(localConstUse, decomplib, currentProgram, refFunc, refAddr,
						funcVarUse, paramIndex, localDefUseList, funcList);
					addConstants(tableChooserDialog, localConstUse);
				}

				constUse.putAll(localConstUse);
			}
		}

		return constUse;
	}

	private void addErrorNote(Address address, String problem) {
		this.addConstantProblem(tableDialog, address, problem);
	}

	private void analyzeFunction(HashMap<Address, Long> constUse, DecompInterface decompInterface,
			Program prog, Function f, Address refAddr, FunctionParamUse funcVarUse, int paramIndex,
			ArrayList<PcodeOp> defUseList, ArrayList<FunctionParamUse> funcList) {
		if (f == null) {
			return;
		}

		decompileFunction(f, decompInterface);

		Instruction instr = prog.getListing().getInstructionAt(refAddr);
		if (hfunction == null) {
			return;
		}
		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps(refAddr.getPhysicalAddress());
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
				// get the second parameter
				Varnode parm = pcodeOpAST.getInput(paramIndex + 1); // 1st param is the call dest
				if (parm == null) {
					constUse.put(instr.getAddress(), null);
					String problem = "  *** Warning, it appears that function '" +
						funcVarUse.getName() + "' at " + funcVarUse.getAddress() +
						" does not have it's parameters recovered!\n" +
						"        Use Commit Params/Return in the decompiler on this function.";
					addErrorNote(instr.getAddress(), problem);
					break;
				}
				// see if it is a constant
				if (parm.isConstant() || parm.isAddress()) {
					// then this is a resource id
					// lookup the resource and create a reference
					long value = parm.getOffset();
					// TODO: not so fast, if there is a defUseList, must apply
					// it to get the real constant USED!
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(instr.getAddress(), value);
						println("   " + f.getName() + "    " + instr.getAddress() + " : 0x" +
							Long.toHexString(value));
					}
					catch (InvalidInputException exc) {
						// do nothing
					}
				}
				else {
					followToParam(constUse, defUseList, hfunction, parm, funcList, null);
				}
				break;
				// if this is anything else, get the high variable to see if it
				// can be traced back to a param
				// then repeat with any calls to this function at whatever the
				// param is
			}
			else if (pcodeOpAST.getOpcode() == PcodeOp.BRANCH) {
				Address faddr = pcodeOpAST.getInput(0).getAddress();
				if (funcVarUse == null || faddr == null) {
					continue;
				}
				if (!faddr.equals(funcVarUse.getAddress())) {
					continue;
				}
				Varnode rep = funcVarUse.getRepresentative();
				if (rep == null) {
					continue;
				}
				followToParam(constUse, defUseList, hfunction, rep, funcList, null);
			}
		}
	}

	private long applyDefUseList(long value, ArrayList<PcodeOp> defUseList)
			throws InvalidInputException {
		if (defUseList == null || defUseList.size() <= 0) {
			return value;
		}
		Iterator<PcodeOp> iterator = defUseList.iterator();
		while (iterator.hasNext()) {
			PcodeOp pcodeOp = iterator.next();
			int opcode = pcodeOp.getOpcode();
			switch (opcode) {
				case PcodeOp.INT_AND:
					if (pcodeOp.getInput(0).isConstant()) {
						value = value & pcodeOp.getInput(0).getOffset();
					}
					else if (pcodeOp.getInput(1).isConstant()) {
						value = value & pcodeOp.getInput(1).getOffset();
					}
					else {
						throw new InvalidInputException(
							" Unhandled Pcode OP " + pcodeOp.toString());
					}
					break;
				default:
					throw new InvalidInputException(" Unhandled Pcode OP " + pcodeOp.toString());
			}
		}
		return value;
	}

	private void followToParam(HashMap<Address, Long> constUse, ArrayList<PcodeOp> defUseList,
			HighFunction highFunction, Varnode vnode, ArrayList<FunctionParamUse> funcList,
			HashSet<SequenceNumber> doneSet) {

		// follow back up through
		PcodeOp def = vnode.getDef();
		Function function = highFunction.getFunction();
		if (def == null) {
			HighVariable hvar = vnode.getHigh();
			if (hvar instanceof HighParam) {
				funcList.add(new FunctionParamUse(function.getName(), function.getEntryPoint(),
					((HighParam) hvar).getSlot(), hvar.getRepresentative(), defUseList));
				return;
			}
			if (hvar instanceof HighGlobal) {
				followThroughGlobal(constUse, defUseList, hvar, funcList, doneSet);
			}
			return;
		}

		// have we done this vnode source already?
		Address funcEntry = function.getEntryPoint();
		SequenceNumber seqNum = def.getSeqnum();
		remapAddress(funcEntry, def.getOutput().getPCAddress());

		if (doneSet == null) {
			doneSet = new HashSet<SequenceNumber>();
		}
		if (seqNum != null && doneSet.contains(seqNum)) {
			return;
		}
		doneSet.add(seqNum);

		int opcode = def.getOpcode();
		switch (opcode) {
			case PcodeOp.COPY:
				if (def.getInput(0).isConstant()) {
					long value = def.getInput(0).getOffset();
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							value);
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(value));
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.LOAD:
				if (def.getInput(0).isConstant() && def.getInput(1).isConstant()) {
					long space = def.getInput(0).getOffset();
					long offset = def.getInput(1).getOffset();
					if (space != funcEntry.getAddressSpace().getSpaceID()) {
						break;
					}
					try {
						offset = applyDefUseList(offset, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							offset);
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(offset));
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.INT_ZEXT:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.MULTIEQUAL:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				@SuppressWarnings("unchecked")
				ArrayList<PcodeOp> splitUseList = (ArrayList<PcodeOp>) defUseList.clone();
				followToParam(constUse, splitUseList, highFunction, def.getInput(1), funcList,
					doneSet);
				return;
			case PcodeOp.CAST:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.INDIRECT:
				Varnode output = def.getOutput();
				if (output.getAddress().equals(def.getInput(0).getAddress())) {
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				if (def.getInput(0).isUnique()) {
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				break;
			case PcodeOp.INT_AND:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				break;
			case PcodeOp.INT_ADD:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				if (vnode.getHigh() instanceof HighParam) {
					// Do nothing
				}
				break;
			case PcodeOp.PTRADD: // Pointer + some offset (usually an array access)
				// if (!def.getInput(1).isConstant() ||
				// !def.getInput(2).isConstant()) {
				// break;
				// }
				// DataType outDt = def.getOutput().getHigh().getDataType();
				// println ("        type = " + outDt.getName());
				// long value = getSigned(def.getInput(1)) *
				// def.getInput(2).getOffset();
				//
				// try {
				// value = applyDefUseList(value, defUseList);
				// constUse.put(def.getOutput().getPCAddress(), value);
				// } catch (InvalidInputException exc) {}
				break;

			case PcodeOp.PTRSUB: // Pointer + some sub element access (usually a
								// structure ref)
				Varnode offsetVal = def.getInput(1);
				if (!offsetVal.isConstant()) {
					break;
				}
				Varnode baseVal = def.getInput(0);
				if (baseVal.isConstant()) {
					// both constant, just use it and return the address
					long value = baseVal.getOffset() + offsetVal.getOffset();
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							value);
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(value));
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				// TODO: handle access into data structure
				// DataType inDt = def.getInput(0).getHigh().getDataType();
				// DataType subDt = def.getOutput().getHigh().getDataType();
				// println ("        type = " + subDt.getName());
				// long subOff = getSigned(def.getInput(1));
				// outDt = subDt;
				// if (subDt instanceof Pointer) {
				// outDt = ((Pointer) subDt).getDataType();
				// if (outDt == null) {
				// }
				// }
				// try {
				// subOff = applyDefUseList(subOff, defUseList);
				// constUse.put(def.getOutput().getPCAddress(), subOff);
				// } catch (InvalidInputException exc) {}
				break;
		}

		constUse.put(remapAddress(funcEntry, vnode.getPCAddress()), null);
		println("   " + function.getName() + "    " + vnode.getPCAddress() + " : Lost");
		// println("     Lost IT! " + vnode.getPCAddress());
	}

	private void followThroughGlobal(HashMap<Address, Long> constUse, ArrayList<PcodeOp> defUseList,
			HighVariable hvar,
			ArrayList<FunctionParamUse> funcList,
			HashSet<SequenceNumber> doneSet) {
		Address loc = hvar.getRepresentative().getAddress();
		PcodeOp def = hvar.getRepresentative().getDef();
		SequenceNumber seqnum = null;
		if (def != null) {
			seqnum = def.getSeqnum();
			if (doneSet.contains(seqnum)) {
				return;
			}
		}
		else {
			seqnum = new SequenceNumber(loc, 0);
		}

		ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(loc);
		while (referencesTo.hasNext()) {
			Reference reference = referencesTo.next();
			if (!reference.getReferenceType().isWrite()) {
				continue;
			}
			currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
			Address refAddr = reference.getFromAddress();
			addErrorNote(refAddr, "Write to global variable");
		}

		doneSet.add(seqnum);
	}

	private Address remapAddress(Address funcEntry, Address address) {
		if (funcEntry.getAddressSpace().isOverlaySpace()) {
			address = funcEntry.getAddressSpace().getOverlayAddress(address);
		}
		return address;
	}

	// Decompiler stuff - cache some information about the last decompilation
	private HighFunction hfunction = null;

	private Address lastDecompiledFuncAddr = null;

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public DecompileResults decompileFunction(Function f, DecompInterface decompInterface) {
		// don't decompile the function again if it was the same as the last one
		//
		if (!f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
			lastResults = decompInterface.decompileFunction(f,
				decompInterface.getOptions().getDefaultTimeout(), monitor);
		}

		hfunction = lastResults.getHighFunction();

		lastDecompiledFuncAddr = f.getEntryPoint();

		return lastResults;
	}
}
