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
//   Attempt to detect functions that jump to another function to share their return.

//
//   This script finds locations in functions that jump to the head of another
//   function and suggests them as shared return.
//   Once the location of a shared return jump is "fixed" by the fixup button, the
//   jump is replaced by a call/return flow overrride.  This fixes up the decompiler,
//   and the body of the function.
//
//   No code, or bad disassembly marks are cleared.
//
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindSharedReturnFunctionsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Program cp = currentProgram;

		TableChooserExecutor executor = createTableExecutor();
		TableChooserDialog tableDialog =
			createTableChooserDialog("Suspect Shared-Return Jump to Functions", executor);
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Searching...");

		detectSharedReturn(cp, tableDialog);

		tableDialog.setMessage("Choose entries to be made Shared-Return Jump Locations");
	}

	private void configureTableColumns(TableChooserDialog tableDialog) {
		StringColumnDisplay explanationColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Explanation";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				SharedReturnLocations entry = (SharedReturnLocations) rowObject;
				return entry.getExplanation();
			}
		};

		StringColumnDisplay funcColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Shared Return Func";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				SharedReturnLocations entry = (SharedReturnLocations) rowObject;
				Function func = entry.getProgram()
						.getFunctionManager()
						.getFunctionContaining(
							entry.getWhyAddr());
				if (func == null) {
					return "";
				}
				return func.getName();
			}
		};

		StringColumnDisplay jumpFromColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Jump Return Func";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				SharedReturnLocations entry = (SharedReturnLocations) rowObject;
				Function func = entry.getProgram()
						.getFunctionManager()
						.getFunctionContaining(
							entry.getAddress());
				if (func == null) {
					return "";
				}
				return func.getName();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		ColumnDisplay<Address> jumpToColumn = new AbstractComparableColumnDisplay<Address>() {
			@Override
			public String getColumnName() {
				return " Shared Func Addr ";
			}

			@Override
			public Address getColumnValue(AddressableRowObject rowObject) {
				SharedReturnLocations noReturnLocations = (SharedReturnLocations) rowObject;
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
				SharedReturnLocations noReturnLocations = (SharedReturnLocations) rowObject;
				return noReturnLocations.getStatus().toString();
			}
		};

		tableDialog.addCustomColumn(jumpFromColumn);
		tableDialog.addCustomColumn(jumpToColumn);
		tableDialog.addCustomColumn(funcColumn);
		tableDialog.addCustomColumn(statusColumn);
		tableDialog.addCustomColumn(explanationColumn);
	}

	private TableChooserExecutor createTableExecutor() {
		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Fixup SharedReturn";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				SharedReturnLocations sharedRetLoc = (SharedReturnLocations) rowObject;
				println("Fixup Shared Return Jump at : " + rowObject.getAddress());

				Program cp = sharedRetLoc.getProgram();
				Address entry = sharedRetLoc.getAddress();

				addBookMark(cp, entry, "Shared Return Jump");

				if (!sharedRetLoc.getStatus().equals("fixed")) {
					fixSharedReturnLocation(cp, entry);
				}

				addBookMark(cp, sharedRetLoc.getWhyAddr(), sharedRetLoc.getExplanation());
				return false;  // don't remove row
			}

			private void fixSharedReturnLocation(Program cp, Address entry) {
				Instruction instr = cp.getListing().getInstructionAt(entry);
				instr.setFlowOverride(FlowOverride.CALL_RETURN);
			}
		};
		return executor;
	}

	class SharedReturnLocations implements AddressableRowObject {
		private Program program;
		private Address addr;
		private Address whyAddr;
		private String explanation;

		SharedReturnLocations(Program prog, Address suspectSharedReturnAddr, Address whyAddr,
				String explanation) {
			this.addr = suspectSharedReturnAddr;
			this.whyAddr = whyAddr;
			this.explanation = explanation;
			this.program = prog;
		}

		public Program getProgram() {
			return program;
		}

		@Override
		public Address getAddress() {
			return getSharedReturnAddr();
		}

		public Address getSharedReturnAddr() {
			return addr;
		}

		public Address getWhyAddr() {
			return whyAddr;
		}

		public String getExplanation() {
			return explanation;
		}

		public String getStatus() {
			Instruction instr = program.getListing().getInstructionAt(addr);
			if (instr == null) {
				return "- no instr -";
			}
			if (!instr.getFlowType().isJump()) {
				return "fixed";
			}
			return "";
		}
	}

	private AddressSet detectSharedReturn(Program cp, TableChooserDialog tableDialog) {
		monitor.setMessage("Detecting Shared-Returning Functions");
		// For each Function
		//  
		//  
		FunctionIterator fiter = currentProgram.getFunctionManager().getFunctions(true);
		AddressSet set = new AddressSet();
		while (fiter.hasNext()) {
			Function function = fiter.next();
			Address entry = function.getEntryPoint();

			// Get all References to the function
			//    If all the refs are calls, no problem.
			//    If some are calls, and some are jumps, problems.
			//    If all are Jumps, then problem
			ReferenceIterator refIter = cp.getReferenceManager().getReferencesTo(entry);
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (ref.getReferenceType().isCall()) {
					continue;
				}
			}

			AddressSetView body = function.getBody();

			refIter = cp.getReferenceManager().getReferencesTo(entry);
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (!ref.getReferenceType().isJump()) {
					continue;
				}
				// jumps to the top of this function, don't count
				if (body.contains(ref.getFromAddress())) {
					continue;
				}
				Address jumpFromAddr = ref.getFromAddress();
				// NOTE: destination block iterator does not handle data/undefined at fallthru location
				SharedReturnLocations location = new SharedReturnLocations(currentProgram,
					jumpFromAddr, entry, "Jumps to called location");
				tableDialog.add(location);
				set.addRange(entry, entry);
			}
		}
		return set;
	}

	private void addBookMark(Program cp, Address addr, String msg) {
		BookmarkManager bookmarkManager = cp.getBookmarkManager();
		if (bookmarkManager.getBookmark(addr, BookmarkType.NOTE,
			"FixupSharedReturnFunctions Script") == null) {
			bookmarkManager.setBookmark(addr, BookmarkType.NOTE,
				"FixupSharedReturnFunctions Script", msg);
		}
	}
}
