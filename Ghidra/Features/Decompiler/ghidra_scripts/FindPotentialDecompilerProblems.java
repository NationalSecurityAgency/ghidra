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
//  This script runs the decompiler on each currently defined function.
//  Function that has potential issues in the decompiler output is flagged in a table with a suggestion.
//  For example any references to "in_" variables, or "unaff_" are flagged with a potential solution.
//  This script is still a work in progress, but it can help diagnose initial analysis of a binary for problems that
//  affect decompiled output and thus the cleanness of code for follow on uses.  Things like unidentified
//  epilog functions that have side-effects on the stack will be uncovered.
//
// @category Analysis

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class FindPotentialDecompilerProblems extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (isRunningHeadless()) {
			printf("This script cannot be run in headless mode.\n");
			return;
		}

		TableChooserDialog tableDialog = createTableChooserDialog(
			"Possible Decompiler Problems: " + currentProgram.getName(), null);
		configureTableColumns(tableDialog);
		tableDialog.show();
		IssueEntries entryList = new TableEntryList(tableDialog);

		DecompilerCallback<Void> callback =
			new DecompilerCallback<Void>(currentProgram, new BasicConfigurer(currentProgram)) {

				@Override
				public Void process(DecompileResults results, TaskMonitor tMonitor)
						throws Exception {
					for (ProblemLocation probLoc : processFunc(results)) {
						entryList.add(probLoc);
					}
					return null;
				}
			};

		Set<Function> funcsToDecompile = new HashSet<>();
		FunctionIterator fIter = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		fIter.forEach(e -> funcsToDecompile.add(e));

		if (funcsToDecompile.isEmpty()) {
			popup("No functions to decompile!");
			return;
		}

		ParallelDecompiler.decompileFunctions(callback, funcsToDecompile, monitor);
		monitor.checkCanceled();
		tableDialog.setMessage("Finished");
	}

	private List<ProblemLocation> processFunc(DecompileResults decompResult) {

		//TODO: skip if func name contains SEH_epilog or SEH_prolog?
		//add general way to have architecture-specific messages?

		List<ProblemLocation> problems = new ArrayList<>();
		Function func = decompResult.getFunction();
		HighFunction hf = decompResult.getHighFunction();
		if (hf == null) {
			problems.add(new ProblemLocation(currentProgram, func.getEntryPoint(),
				func.getEntryPoint(), "", "Decompilation Error"));
			return problems;
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
				String possible =
					"Function signature missing register param, called function passed too many register params, or only a subpiece" +
						" of a register actually used.";
				if (!(hf.getFunction().getSymbol().isGlobal()) &&
					!(hf.getFunction().getCallingConventionName().contains("thiscall"))) {
					possible += " Function might need calling convention changed to thiscall";
				}
				if (sym.getName().startsWith("in_stack_ff")) {
					possible =
						"Too many stack parameters passed to a called function.  May need to redefine in the called function (could be varargs).";
				}
				if (sym.getName().startsWith("in_stack_00")) {
					possible =
						"Too few stack parameters defined for this function.  May need to redefine parameters.";
				}

				Address funcAddr =
					getFirstFuncWithVar(func, sym.getHighVariable().getRepresentative());

				//if we didn't find a good location for the cause of the problem, 
				//just use the entry point of the function with the problem
				if (funcAddr == null || funcAddr.equals(Address.NO_ADDRESS)) {
					funcAddr = func.getEntryPoint();
				}
				problems.add(new ProblemLocation(currentProgram, func.getEntryPoint(), funcAddr,
					sym.getName(), possible));
			}

			if (sym.getName().startsWith("unaff_")) {
				Address firstAddr = getFirstCalledFunction(func);
				if (sym.getName().equals("unaff_EBP")) {
					problems.add(
						new ProblemLocation(currentProgram, firstAddr, func.getEntryPoint(),
							sym.getName(), "Suspect function is EH_PROLOG/EH_EPILOG"));
					continue;
				}
				// Has a side effect variable
				String possible = (firstAddr != null ? "Side effect from a call"
						: "Undefined parameter or global register save");
				//TODO: sym.getPCAddress() points outside of function bodies in certain cases...
				problems.add(new ProblemLocation(currentProgram, func.getEntryPoint(),
					sym.getPCAddress(), sym.getName(), possible));
			}
			//extraout_X: will sym.getHighVariable().getRepresentative return X?
			if (sym.getName().startsWith("extraout")) {
				// Has a side effect variable
				Address funcAddr =
					getFirstFuncWithVar(func, sym.getHighVariable().getRepresentative());

				if (funcAddr.equals(Address.NO_ADDRESS)) {
					funcAddr = func.getEntryPoint();
				}

				String possible =
					"Bad parameter in called function or extra return value/global register/function register side effect";
				if (sym.getName().startsWith("extraout_var")) {
					possible = "Function containing problem may need return type adjusted.";
				}
				problems.add(new ProblemLocation(currentProgram, func.getEntryPoint(), funcAddr,
					sym.getName(), possible));
			}
		}
		return problems;
	}

	/**
	 * Returns the target of the first (in address order) call in the body of {@code func}
	 * which takes {@code vn} as a parameter.
	 * @param func {@link Function} whose body to search for calls
	 * @param vn {@link Varnode} representing required parameter
	 * @return entry point of first function called by {@code func} which uses {@code vn}
	 * as a parameter, or {@code Address.NO_ADDRESS} if no such function found.
	 */
	private Address getFirstFuncWithVar(Function func, Varnode vn) {
		Address variableAddr = vn.getAddress();
		if (variableAddr == null) {
			return Address.NO_ADDRESS;
		}

		// Note: this handles some cases where functions consist of non-contiguous blocks,
		// but since we start at the entry point we might miss things if part of the body of
		// the function is before the entry point (in address order)
		ReferenceIterator refIter =
			func.getProgram().getReferenceManager().getReferenceIterator(func.getEntryPoint());

		Address maxAddr = func.getBody().getMaxAddress();

		// return the first call to a function which takes vn as an argument
		for (Reference ref : CollectionUtils.asIterable(refIter)) {
			// check whether we are at an address not in the function
			// only necessary in case func consists of non-contiguous blocks
			// TODO: handle tail-call elimination
			if (!func.getBody().contains(ref.getFromAddress())) {
				continue;
			}
			if (isValidCallReference(ref)) {
				Function calledFunc =
					currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
				Parameter[] params = calledFunc.getParameters();
				for (Parameter param : params) {
					Address addr = param.getMinAddress();
					if (addr != null && addr.equals(variableAddr)) {
						return ref.getToAddress();
					}
				}
			}
			// The references are sorted by their "from" addresses, so if this condition is true, 
			// we've searched all the references from the body of func and haven't found anything.
			// So, stop looking.
			if (ref.getFromAddress().compareTo(maxAddr) > 0) {
				return Address.NO_ADDRESS;
			}
		}
		//in case there are no references with "from" addresses after the body of func
		return Address.NO_ADDRESS;
	}

	/**
	 * Returns the address of first function called by {@code func}.  That is, the returned {@link Address}
	 * is the target of the call instruction with the least address within the body of {@code func}. 
	 * @param func the {@link Function} to search for calls
	 * @return the {@link Address} of the first called function, or {@code Address.NO_ADDRESS} if
	 * no calls are found.
	 */
	private Address getFirstCalledFunction(Function func) {

		//could be issues if func's body has addresses that are before the entry point of
		//func - see the comment in getFirstFuncWithVar
		ReferenceIterator refIter =
			func.getProgram().getReferenceManager().getReferenceIterator(func.getEntryPoint());

		Address maxAddr = func.getBody().getMaxAddress();

		for (Reference ref : CollectionUtils.asIterable(refIter)) {
			// check whether we are at an address not in the function
			// only necessary in case func consists of non-contiguous blocks
			// TODO: handle tail-call elimination
			if (!func.getBody().contains(ref.getFromAddress())) {
				continue;
			}

			// return the first call for the function
			if (isValidCallReference(ref)) {
				return ref.getToAddress();
			}
			// The references are sorted by their "from" addresses, so if this condition is true, 
			// we've searched all the references from the body of func and haven't found anything.
			// So, stop looking.
			if (ref.getFromAddress().compareTo(maxAddr) > 0) {
				return Address.NO_ADDRESS;
			}
		}
		//in case there are no references with "from" addresses after the body of func
		return Address.NO_ADDRESS;
	}

	//returns true precisely when ref is a call reference to a defined function
	private boolean isValidCallReference(Reference ref) {
		if (!ref.getReferenceType().isCall()) {
			return false;
		}
		if (ref.getToAddress() == null) {
			return false;
		}
		if (currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress()) != null) {
			return true;
		}
		return false;

	}

	static class BasicConfigurer implements DecompileConfigurer {
		private Program p;

		public BasicConfigurer(Program prog) {
			p = prog;
		}

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(p);
			decompiler.setOptions(opts);
		}
	}

	////////////////////////////////////////////////////////////////////////////////////
	//                          table stuff                                           //
	////////////////////////////////////////////////////////////////////////////////////

	private void configureTableColumns(TableChooserDialog dialog) {
		StringColumnDisplay explanationColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Potential Problem";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocation entry = (ProblemLocation) rowObject;
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
				ProblemLocation entry = (ProblemLocation) rowObject;
				Function func = entry.getProgram().getFunctionManager().getFunctionContaining(
					entry.getAddress());
				if (func == null) {
					return "";
				}
				return func.getName();
			}
		};

		ColumnDisplay<Address> probLocColumn = new ColumnDisplay<Address>() {
			@Override
			public String getColumnName() {
				return "Location of Possible Cause";
			}

			@Override
			public Address getColumnValue(AddressableRowObject rowObject) {
				ProblemLocation probLocation = (ProblemLocation) rowObject;
				return probLocation.getWhyAddr();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}

			@Override
			public Class<Address> getColumnClass() {
				return Address.class;
			}
		};

		StringColumnDisplay varNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Problematic Variable";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ProblemLocation probLocation = (ProblemLocation) rowObject;
				return probLocation.getVarName();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		dialog.addCustomColumn(funcColumn);
		dialog.addCustomColumn(probLocColumn);
		dialog.addCustomColumn(varNameColumn);
		dialog.addCustomColumn(explanationColumn);
	}

	class ProblemLocation implements AddressableRowObject {
		private Program program;
		private Address problemAddress;
		private Address causeAddress;
		private String varName;
		private String explanation;

		ProblemLocation(Program prog, Address problemAddress, Address whyAddr, String varName,
				String explanation) {
			this.problemAddress = problemAddress;
			this.causeAddress = whyAddr;
			this.varName = varName;
			this.explanation = explanation;
			this.program = prog;
		}

		public Program getProgram() {
			return program;
		}

		@Override
		public Address getAddress() {
			return getFuncAddr();
		}

		public Address getFuncAddr() {
			if (problemAddress == null) {
				return Address.NO_ADDRESS;
			}
			return problemAddress;
		}

		public Address getWhyAddr() {
			if (causeAddress == null) {
				return Address.NO_ADDRESS;
			}
			return causeAddress;
		}

		public String getVarName() {
			return varName;
		}

		public String getExplanation() {
			return explanation;
		}

		@Override
		public String toString() {
			return "Issue at:" + getAddress() + "  found: " + getVarName() + "  " +
				getExplanation() + " at " + getWhyAddr();
		}
	}

	interface IssueEntries {

		void add(ProblemLocation location);

		int getNumEntries();

		void setMessage(String string);

	}

	class TableEntryList implements IssueEntries {

		private TableChooserDialog tableDialog;

		public TableEntryList(TableChooserDialog tableDialog) {
			this.tableDialog = tableDialog;
		}

		@Override
		public void add(ProblemLocation location) {
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

}
