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
// Finds potential problems in code that will cause trouble for the decompiler.
//
// This script essentially runs the decompiler on each currently defined function.
//  Any function that has potential issues in the decompiler output is flagged in a table with a suggestion.
//  For example any references to "in_" variables, or "unaff_" are flagged with a potential solution.
//  This is very prototype at this point, but it can help diagnose initial analysis of a binary for problems that
//  affect decompiled output and thus the cleaness of code for follow on uses.  Things like unidentified
//  epilog functions that have side-effects on the stack will be uncovered.
//
// @category Analysis

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindPotentialDecompilerProblems extends GhidraScript {

	private IssueEntries entryList = null;

	private DecompInterface decomplib;
	DecompileResults lastResults = null;

	@Override
	public void run() throws Exception {

		TableChooserDialog tableDialog = null;

		TableChooserExecutor executor = null;

		try {
			if (this.isRunningHeadless()) {
				entryList = new IssueEntryList();
			}
			else {
				tableDialog =
					createTableChooserDialog("Decompiler Inconsistency Problems", executor);
				configureTableColumns(tableDialog);
				tableDialog.show();
				tableDialog.setMessage("Searching...");
				entryList = new TableEntryList(tableDialog);
			}

			// get the decompiler context
			// setup the decompiler
			decomplib = setUpDecompiler(currentProgram);

			FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
			while (funcIter.hasNext() && !monitor.isCancelled()) {
				Function func = funcIter.next();

				// no real function here.
				if (currentProgram.getListing().getInstructionAt(func.getEntryPoint()) == null) {
					continue;
				}

				if (tableDialog != null) {
					tableDialog.setMessage("Decompiling - " + func.getName());
				}

				DecompileResults decompResult = decompileFunction(func, decomplib);

				HighFunction hf = decompResult.getHighFunction();
				if (hf == null) {
					entryList.add(new ProblemLocations(currentProgram, func.getEntryPoint(), null,
						"", "Decompilation Error"));
					continue;
				}

				Iterator<HighSymbol> symIter = hf.getLocalSymbolMap().getSymbols();
				while (symIter.hasNext() && !monitor.isCancelled()) {
					HighSymbol sym = symIter.next();
					HighVariable highVar = sym.getHighVariable();
					if (!(highVar instanceof HighLocal)) {
						continue;
					}

					if (sym.getName().startsWith("in_") && !sym.getName().equals("in_FS_OFFSET")) {
						// Has an input variable that is not a parameter
						Address funcAddr =
							getFirstFuncWithVar(func, sym.getHighVariable().getRepresentative());
						String badness =
							"Missing input register param, or bad register param defined in called function";
						if (sym.getName().startsWith("in_stack_ff")) {
							badness =
								"Too many stack parameters defined in a called function.  May need to redefine in the called function.";
						}
						if (sym.getName().startsWith("in_stack_00")) {
							badness =
								"Too few stack parameters defined for this function.  May need to redfine parameters.";
						}
						entryList.add(new ProblemLocations(currentProgram, func.getEntryPoint(),
							funcAddr, sym.getName(), badness));
					}
					if (sym.getName().startsWith("unaff_")) {
						Address firstAddr = getFirstCalledFunction(func);
						if (sym.getName().equals("unaff_EBP")) {
							entryList.add(new ProblemLocations(currentProgram, firstAddr,
								func.getEntryPoint(), sym.getName(),
								"Suspect function is EH_PROLOG setup"));
							continue;
						}
						// Has a sideffect variable
						String possible = (firstAddr != null ? "Sideffect from a call"
								: "Undefined paramter or global register save");
						entryList.add(new ProblemLocations(currentProgram, func.getEntryPoint(),
							sym.getPCAddress(), sym.getName(), possible));
					}
					if (sym.getName().startsWith("extraout")) {
						// Has a sideffect variable
						Address funcAddr =
							getFirstFuncWithVar(func, sym.getHighVariable().getRepresentative());
						if (funcAddr == null) {
							funcAddr = sym.getHighVariable().getRepresentative().getAddress();
						}
						String possible = (funcAddr != null ? "Bad paramter in called function"
								: "Extra return value, Global register, or Function register Sideffect");
						if (sym.getName().startsWith("extraout_var")) {
							possible =
								"Called function does not return a Solid type.  Undefined4 might need to be int.";
						}
						entryList.add(new ProblemLocations(currentProgram, funcAddr,
							func.getEntryPoint(), sym.getName(), possible));
					}
				}
			}

			if (this.isRunningHeadless()) {
				// Do the cases, or just create a selection
				IssueEntryList issueList = (IssueEntryList) entryList;
				int numEntries = issueList.getNumEntries();
				for (int i = 0; i < numEntries; i++) {
					ProblemLocations entry = issueList.getEntry(i);
					if (entry.isFixed()) {
						continue;
					}
					println(entry.toString());
					// this will actually do the fixup for all places currently
					// calling this location
					if (executor != null) {
						executor.execute(entry);
					}
				}

			}
			else {
				entryList.setMessage("Found Potential Problems");
			}
		}
		finally {
			tableDialog.setMessage("Finished");
			decomplib.dispose();
		}
	}

	private Address getFirstFuncWithVar(Function func, Varnode vn) {
		Address variableAddr = vn.getAddress();
		if (variableAddr == null) {
			return Address.NO_ADDRESS;
		}
		ReferenceIterator riter =
			func.getProgram().getReferenceManager().getReferenceIterator(func.getEntryPoint());
		while (riter.hasNext()) {
			Reference ref = riter.next();
			if (!func.getBody().contains(ref.getFromAddress())) {
				return Address.NO_ADDRESS;
			}
			// return the first call for the function
			if (ref.getReferenceType().isCall()) {
				if (ref.getToAddress() == null) {
					continue;
				}
				Function calledFunc =
					func.getProgram().getFunctionManager().getFunctionAt(ref.getToAddress());
				if (calledFunc == null) {
					continue;
				}
				Parameter[] params = calledFunc.getParameters();
				for (Parameter param : params) {
					Address addr = param.getMinAddress();
					if (addr != null && addr.equals(variableAddr)) {
						return ref.getToAddress();
					}
				}
			}
		}
		return Address.NO_ADDRESS;
	}

	private Address getFirstCalledFunction(Function func) {
		ReferenceIterator riter =
			func.getProgram().getReferenceManager().getReferenceIterator(func.getEntryPoint());
		while (riter.hasNext()) {
			Reference ref = riter.next();
			if (!func.getBody().contains(ref.getFromAddress())) {
				return Address.NO_ADDRESS;
			}
			// return the first call for the function
			if (ref.getReferenceType().isCall()) {
				return ref.getToAddress();
			}
		}
		return Address.NO_ADDRESS;
	}

	private Address lastDecompiledFuncAddr = null;

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

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

		decompInterface.openProgram(program);

		return decompInterface;
	}

	public DecompileResults decompileFunction(Function f, DecompInterface decompInterface) {
		// don't decompile the function again if it was the same as the last one
		//
		if (f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
			return lastResults;
		}

		lastResults = null;

		lastResults = decompInterface.decompileFunction(f,
			decompInterface.getOptions().getDefaultTimeout(), monitor);

		lastDecompiledFuncAddr = f.getEntryPoint();

		return lastResults;
	}

	private void configureTableColumns(TableChooserDialog dialog) {
		StringColumnDisplay explanationColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Potential Problem";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocations entry = (ProblemLocations) rowObject;
				return entry.getExplanation();
			}
		};

		StringColumnDisplay funcColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Func Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocations entry = (ProblemLocations) rowObject;
				Function func = entry.getProgram().getFunctionManager().getFunctionContaining(
					entry.getAddress());
				if (func == null) {
					return "";
				}
				return func.getName();
			}
		};

		ColumnDisplay<Address> probLocColumn = new AbstractComparableColumnDisplay<Address>() {
			@Override
			public String getColumnName() {
				return "Problem Loc";
			}

			@Override
			public Address getColumnValue(AddressableRowObject rowObject) {
				ProblemLocations probLocation = (ProblemLocations) rowObject;
				return probLocation.getWhyAddr();
			}
		};

		StringColumnDisplay varNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Var Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocations probLocation = (ProblemLocations) rowObject;
				return probLocation.getVarName();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		StringColumnDisplay statusColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Status";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocations probLocation = (ProblemLocations) rowObject;
				return probLocation.getStatus().toString();
			}
		};

		dialog.addCustomColumn(funcColumn);
		dialog.addCustomColumn(statusColumn);
		dialog.addCustomColumn(probLocColumn);
		dialog.addCustomColumn(varNameColumn);
		dialog.addCustomColumn(explanationColumn);
	}

	class ProblemLocations implements AddressableRowObject {
		private Program program;
		private Address addr;
		private Address whyAddr;
		private String varName;
		private String explanation;
		private String status;

		ProblemLocations(Program prog, Address suspectNoRetAddr, Address whyAddr, String varName,
				String explanation) {
			this.addr = suspectNoRetAddr;
			this.whyAddr = whyAddr;
			this.varName = varName;
			this.explanation = explanation;
			this.program = prog;
		}

		public boolean isFixed() {
			return getStatus().equals("fixed");
		}

		public void setStatus(String status) {
			this.status = status;
		}

		public Program getProgram() {
			return program;
		}

		@Override
		public Address getAddress() {
			return getFuncAddr();
		}

		public Address getFuncAddr() {
			if (addr == null) {
				return Address.NO_ADDRESS;
			}
			return addr;
		}

		public Address getWhyAddr() {
			if (whyAddr == null) {
				return Address.NO_ADDRESS;
			}
			return whyAddr;
		}

		public String getVarName() {
			return varName;
		}

		public String getExplanation() {
			return explanation;
		}

		public String getStatus() {
			if (status != null) {
				return status;
			}

			return "";
		}

		@Override
		public String toString() {
			return "Issue at:" + getAddress() + "  found: " + getVarName() + "  " +
				getExplanation() + " at " + getWhyAddr();
		}
	}

	interface IssueEntries {

		void add(ProblemLocations location);

		int getNumEntries();

		void setMessage(String string);

	}

	class TableEntryList implements IssueEntries {

		private TableChooserDialog tableDialog;

		public TableEntryList(TableChooserDialog tableDialog) {
			this.tableDialog = tableDialog;
		}

		@Override
		public void add(ProblemLocations location) {
			tableDialog.add(location);
		}

		@Override
		public void setMessage(String string) {
			tableDialog.setMessage(string);
		}

		@Override
		public int getNumEntries() {
			return tableDialog.getRowCount();
		}

	}

	class IssueEntryList implements IssueEntries {

		ArrayList<ProblemLocations> list = new ArrayList<ProblemLocations>();

		@Override
		public void add(ProblemLocations location) {
			list.add(location);
		}

		@Override
		public void setMessage(String string) {
			// do nothing
		}

		@Override
		public int getNumEntries() {
			return list.size();
		}

		public ProblemLocations getEntry(int i) {
			return list.get(i);
		}
	}
}
