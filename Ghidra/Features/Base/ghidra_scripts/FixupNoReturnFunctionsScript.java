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
//
//   Attempt to detect defined functions in a program that don't return.
//   Functions like exit(), abort(), bassert() don't return, and sometimes
//   compilers know this.  They will start the next function or data immediately
//   after the call to the function that is known not to return.
//   This can cause bad disassembly, incestuous functions, etc...
//
//   This script finds functions that don't return by looking at the code that
//   follows all function calls.
//   Once the no-return usage is detected, it marks the offending functions, and
//   everywhere they are called, changes the fallthru of the call.
//   Then each function that had a fixed up call, re-detect the functions body.
//
//   No code, or bad disassembly marks are cleared.
//
//   You can run this script once, and it will add bookmarks at each potential non-returning
//   function, and at each location that calls the function in a suspicious way.
//
//@category Functions

import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

public class FixupNoReturnFunctionsScript extends GhidraScript {

	IssueEntries entryList = null;

	@Override
	public void run() throws Exception {
		Program cp = currentProgram;

		TableChooserExecutor executor = createTableExecutor();

		if (this.isRunningHeadless()) {
			entryList = new IssueEntryList();
		}
		else {
			TableChooserDialog tableDialog =
				createTableChooserDialog("Suspect Non-Returning Functions", executor);
			configureTableColumns(tableDialog);
			tableDialog.show();
			tableDialog.setMessage("Searching...");
			entryList = new TableEntryList(tableDialog);
		}

		detectNoReturn(cp, entryList);

		if (this.isRunningHeadless()) {
			// Do the cases, or just create a selection
			IssueEntryList issueList = (IssueEntryList) entryList;
			int numEntries = issueList.getNumEntries();
			for (int i = 0; i < numEntries; i++) {
				NoReturnLocations entry = issueList.getEntry(i);
				if (entry.isFixed()) {
					continue;
				}
				println(entry.toString());
				// this will actually do the fixup for all places currently calling this location
				executor.execute(entry);
			}

		}
		else {
			entryList.setMessage("Choose entries to be made Non-Returning functions");
		}
	}

	private void configureTableColumns(TableChooserDialog dialog) {
		StringColumnDisplay explanationColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Explanation";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				NoReturnLocations entry = (NoReturnLocations) rowObject;
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
				NoReturnLocations entry = (NoReturnLocations) rowObject;
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

		ColumnDisplay<Address> callFromColumn = new AbstractComparableColumnDisplay<Address>() {
			@Override
			public String getColumnName() {
				return "Call Location";
			}

			@Override
			public Address getColumnValue(AddressableRowObject rowObject) {
				NoReturnLocations noReturnLocations = (NoReturnLocations) rowObject;
				return noReturnLocations.getWhyAddr();
			}
		};

		StringColumnDisplay statusColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Status";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				NoReturnLocations noReturnLocations = (NoReturnLocations) rowObject;
				return noReturnLocations.getStatus().toString();
			}
		};

		dialog.addCustomColumn(funcColumn);
		dialog.addCustomColumn(statusColumn);
		dialog.addCustomColumn(callFromColumn);
		dialog.addCustomColumn(explanationColumn);
	}

	void repairDamage(Program cp, Function func, Address entry) {
		func.setNoReturn(true);

		try {
			String name = func.getName();

			entryList.setMessage("Clearing fallthrough for: " + name);
			setNoFallThru(cp, entry);

			entryList.setMessage("Fixup function bodies for: " + name);
			fixCallingFunctionBody(cp, entry);

			entryList.setMessage("Clearing and repairing flows for: " + name);
			clearAndRepairFlows(cp, entry);
		}
		catch (CancelledException e) {
			// a cancel here implies that the entire script has been cancelled
		}
	}

	protected void setNoFallThru(Program cp, Address entry) {
		ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			Instruction instr = currentProgram.getListing().getInstructionAt(fromAddr);
			if (instr == null) {
				continue;
			}
			Address fallthruAddr = instr.getFallThrough();
			if (fallthruAddr != null) {
				instr.setFlowOverride(FlowOverride.CALL_RETURN);
			}
		}
	}

	protected void clearAndRepairFlows(Program cp, Address entry) throws CancelledException {
		AddressSet clearInstSet = new AddressSet();
		AddressSet clearDataSet = new AddressSet();

		ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			Instruction instr = currentProgram.getListing().getInstructionAt(fromAddr);
			if (instr == null) {
				continue;
			}
			Address fallthruAddr = instr.getFallThrough();
			if (fallthruAddr == null) {
				try {
					fallthruAddr =
						instr.getMinAddress().addNoWrap(instr.getDefaultFallThroughOffset());
				}
				catch (AddressOverflowException e) {
					// handled below
				}
			}
			if (fallthruAddr == null) {
				continue;
			}
			// if location right below is an entry point, don't clear it
			if (currentProgram.getSymbolTable().isExternalEntryPoint(fallthruAddr)) {
				continue;
			}

			if (!hasFlowRefInto(fallthruAddr)) {
				Instruction inst = currentProgram.getListing().getInstructionAt(fallthruAddr);
				if (inst != null) {
					clearInstSet.add(fallthruAddr);
				}
				else {
					clearDataSet.add(fallthruAddr);
				}
			}
		}

		if (!clearInstSet.isEmpty()) {
			// entries including data flow referenced from instructions will be repaired
			ClearFlowAndRepairCmd cmd = new ClearFlowAndRepairCmd(clearInstSet, true, false, true);
			cmd.applyTo(currentProgram, monitor);
		}
		if (!clearDataSet.isEmpty()) {
			// entries that are data should not be cleared, only possible bookmarks
			ClearFlowAndRepairCmd.clearBadBookmarks(currentProgram, clearDataSet, monitor);
		}
	}

	private boolean hasFlowRefInto(Address addr) {
		ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			RefType refType = ref.getReferenceType();
			if (refType.isFlow()) {
				return true;
			}
		}
		return false;
	}

	private TableChooserExecutor createTableExecutor() {
		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Fixup NoReturn";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				NoReturnLocations noRetLoc = (NoReturnLocations) rowObject;
				println("Fixup NoReturn Function at : " + rowObject.getAddress());

				Program cp = noRetLoc.getProgram();
				Address entry = noRetLoc.getAddress();

				Function func = currentProgram.getFunctionManager().getFunctionAt(entry);
				if (func == null) {
					noRetLoc.setStatus("No function at " + entry);
					return false;
				}

				addBookMark(cp, entry, "Non Returning Function");

				if (!noRetLoc.isFixed()) {
					repairDamage(cp, func, entry);
				}

				addBookMark(cp, noRetLoc.getWhyAddr(), noRetLoc.getExplanation());

				return false; // don't remove row
			}
		};

		return executor;
	}

	class NoReturnLocations implements AddressableRowObject {
		private Program program;
		private Address addr;
		private Address whyAddr;
		private String explanation;
		private String status;

		NoReturnLocations(Program prog, Address suspectNoRetAddr, Address whyAddr,
				String explanation) {
			this.addr = suspectNoRetAddr;
			this.whyAddr = whyAddr;
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
			return getNoReturnAddr();
		}

		public Address getNoReturnAddr() {
			return addr;
		}

		public Address getWhyAddr() {
			return whyAddr;
		}

		public String getExplanation() {
			return explanation;
		}

		public String getStatus() {
			if (status != null) {
				return status;
			}

			Instruction instr = program.getListing().getInstructionAt(whyAddr);
			if (instr == null) {
				return "- no instr -";
			}
			if (!instr.hasFallthrough()) {
				return "fixed";
			}
			return "";
		}

		@Override
		public String toString() {
			return "NoReturn At:" + getAddress() + "  because: " + getExplanation() + " at " +
				getWhyAddr();
		}
	}

	private AddressSet detectNoReturn(Program cp, IssueEntries noReturnEntries)
			throws CancelledException {

		// For each Function
		//  
		//  
		FunctionManager functionManager = currentProgram.getFunctionManager();
		FunctionIterator functionIter = functionManager.getFunctions(true);
		AddressSet set = new AddressSet();
		HashSet<Function> suspectNoReturnFunctions = new HashSet<Function>();

		while (functionIter.hasNext()) {
			Function candidateNoReturnfunction = functionIter.next();
			noReturnEntries.setMessage("Checking function: " + candidateNoReturnfunction.getName());

			Address entry = candidateNoReturnfunction.getEntryPoint();

			SimpleBlockModel blockModel = new SimpleBlockModel(cp);

			// Get all References to the function
			// see if any of the refs
			//     fall into other functions or data
			//        directly
			//        basic block below, falls into another function
			//     fall into bad code (or data)
			//
			ReferenceIterator refIter = cp.getReferenceManager().getReferencesTo(entry);
			int isNoReturn = 0;
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (ref.getReferenceType().isCall()) {
					Instruction instr = cp.getListing().getInstructionAt(ref.getFromAddress());
					if (instr == null) {
						continue;
					}
					Address fallThru = instr.getFallThrough();
					if (fallThru == null) {
						continue;
					}
					// if the call falls into the function containing it,
					//    it is most likely an optimization from compiler
					Function callingFunction =
						cp.getFunctionManager().getFunctionContaining(ref.getFromAddress());
					if (callingFunction != null &&
						callingFunction.getEntryPoint().equals(fallThru)) {
						continue;
					}
					// function right after....
					if (testNoReturn(ref, callingFunction, fallThru, blockModel, noReturnEntries)) {
						isNoReturn++;
						continue;
					}
				}
			}

			if (isNoReturn > 0) {
				testCalledFunctionsNonReturning(candidateNoReturnfunction, suspectNoReturnFunctions,
					noReturnEntries);
				set.addRange(entry, entry);
				suspectNoReturnFunctions.add(candidateNoReturnfunction);
			}
		}

		return set;
	}

	private boolean testCalledFunctionsNonReturning(Function candidateNonReturningFunction,
			Set<Function> suspectNoReturnFunctions, IssueEntries dialog) {
		// TODO: should check lower level functions first, to know if they are potentially non-returning
		if (suspectNoReturnFunctions.contains(candidateNonReturningFunction)) {
			return true;
		}
		// look at all functions that the candidate non-returning function calls.
		//   Are any non-returning, or on the suspected noReturnEntries list.
		Set<Function> calledFunctions = candidateNonReturningFunction.getCalledFunctions(monitor);
		for (Function function : calledFunctions) {
			if (function.hasNoReturn()) {
				suspectNoReturnFunctions.add(function);
			}
			if (suspectNoReturnFunctions.contains(function)) {
				NoReturnLocations location = new NoReturnLocations(currentProgram,
					candidateNonReturningFunction.getEntryPoint(), function.getEntryPoint(),
					"Function possibly nonReturning, and calls a non Returning function");
				dialog.add(location);
				return true;
			}
		}
		return false;
	}

	private boolean testNoReturn(Reference ref, Function callingFunc, Address fallThru,
			SimpleBlockModel blockModel, IssueEntries dialog) throws CancelledException {

		FunctionManager funcManager = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		while (fallThru != null) {
			if (funcManager.getFunctionAt(fallThru) != null) {

				NoReturnLocations location = new NoReturnLocations(currentProgram,
					ref.getToAddress(), ref.getFromAddress(), "Function defined after call");
				dialog.add(location);
				return true;
			}
			CodeBlock block = blockModel.getFirstCodeBlockContaining(fallThru, monitor);
			if (block == null) {
				NoReturnLocations location = new NoReturnLocations(currentProgram,
					ref.getToAddress(), ref.getFromAddress(), "Bad block after call");
				dialog.add(location);
				return true;
			}
			// check for read/write refs after
			ReferenceIterator refIterTo =
				currentProgram.getReferenceManager().getReferencesTo(fallThru);
			while (refIterTo.hasNext()) {
				Reference reference = refIterTo.next();
				RefType refType = reference.getReferenceType();
				if (refType.isRead() || refType.isWrite()) {
					// look at function the reference is coming from
					// is the function the same as the call is in
					//    This is a better indicator of non-returning
					// Random references from another function could be bad disassembly
					// or references.  This is especially true if there is only one
					// example for a calling reference.
					if (callingFunc != null) {
						Function function =
							funcManager.getFunctionContaining(reference.getFromAddress());
						if (callingFunc.equals(function)) {
							NoReturnLocations location = new NoReturnLocations(currentProgram,
								ref.getToAddress(), ref.getFromAddress(),
								"Data Reference from same function after call");
							dialog.add(location);
							return true;
						}
					}
					else {
						// only consider references after call if the call location is not in a function
						NoReturnLocations location = new NoReturnLocations(currentProgram,
							ref.getToAddress(), ref.getFromAddress(), "Data Reference after call");
						dialog.add(location);
						return true;
					}
				}
			}
			// check for defined data after
			Data data = listing.getDefinedDataContaining(fallThru);
			if (data != null) {
				NoReturnLocations location = new NoReturnLocations(currentProgram,
					ref.getToAddress(), ref.getFromAddress(), "Data after call");
				dialog.add(location);
				return true;
			}
			fallThru = null;
			if (block.getFlowType().isFallthrough()) {
				CodeBlockReferenceIterator dests = block.getDestinations(monitor);
				if (!dests.hasNext()) {
					// NOTE: destination block iterator does not handle data/undefined at fallthru location
					NoReturnLocations location = new NoReturnLocations(currentProgram,
						ref.getToAddress(), ref.getFromAddress(), "Falls into data after call");
					dialog.add(location);
					return true;
				}
				// Fallthru block has single destination block
				CodeBlockReference destBlock = dests.next();
				if (destBlock.getFlowType().isFallthrough()) {
					fallThru = destBlock.getDestinationAddress();
				}
			}
		}
		return false;
	}

	protected void fixCallingFunctionBody(Program cp, Address entry) throws CancelledException {
		println("** NoReturn func " + cp.getFunctionManager().getFunctionAt(entry).getName());

		AddressSet fixedSet = new AddressSet();

		ReferenceIterator refIter = cp.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			// don't fixup already fixed locations
			if (fixedSet.contains(fromAddr)) {
				continue;
			}
			Function fixFunc = cp.getFunctionManager().getFunctionContaining(fromAddr);
			if (fixFunc == null) {
				continue;
			}
			AddressSetView oldBody = fixFunc.getBody();

			AddressSetView newBody = CreateFunctionCmd.getFunctionBody(cp, fixFunc.getEntryPoint());
			if (oldBody.equals(newBody)) {
				fixedSet.add(newBody);
				continue;
			}
			CreateFunctionCmd.fixupFunctionBody(cp, fixFunc, monitor);
			Function newFunc = cp.getFunctionManager().getFunctionContaining(fromAddr);

			if (newFunc != null) {
				newBody = newFunc.getBody();
				fixedSet.add(newBody);

				if (!oldBody.equals(newBody)) {
					println("Fixed func at " + oldBody.getMinAddress() + " to " +
						newBody.getMinAddress());
				}
			}
		}
	}

	private void addBookMark(Program cp, Address addr, String msg) {
		BookmarkManager bookmarkManager = cp.getBookmarkManager();
		if (bookmarkManager.getBookmark(addr, BookmarkType.NOTE,
			"FixupNoReturnFunctions Script") == null) {
			bookmarkManager.setBookmark(addr, BookmarkType.NOTE, "FixupNoReturnFunctions Script",
				msg);
		}
	}

	interface IssueEntries {

		void add(NoReturnLocations location);

		int getNumEntries();

		void setMessage(String string);

	}

	class TableEntryList implements IssueEntries {

		private TableChooserDialog tableDialog;

		public TableEntryList(TableChooserDialog tableDialog) {
			this.tableDialog = tableDialog;
		}

		@Override
		public void add(NoReturnLocations location) {
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

		ArrayList<NoReturnLocations> list = new ArrayList<NoReturnLocations>();

		@Override
		public void add(NoReturnLocations location) {
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

		public NoReturnLocations getEntry(int i) {
			return list.get(i);
		}
	}
}
