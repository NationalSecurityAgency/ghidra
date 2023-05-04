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
// Displays a table showing locations where the decompiled code writes a value within the containing
// function's body to the stack.  This is a good indication that the decompiler's
// stack analysis is missing information.  For example, the function or a callee might need
// to have its signature, calling convention, or "No Return" status adjusted.

// @category Analysis 

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DecompilerStackProblemsFinderScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (isRunningHeadless()) {
			println("This script cannot be run headlessly");
			return;
		}

		AddressSetView selection = currentSelection;
		if (selection == null) {
			selection = currentProgram.getMemory().getExecuteSet();
		}

		DecompilerCallback<List<StackErrorRow>> callback =
			new DecompilerCallback<>(currentProgram, new StackErrorConfigurer(currentProgram)) {

				@Override
				public List<StackErrorRow> process(DecompileResults results, TaskMonitor tMonitor)
						throws Exception {
					tMonitor.checkCancelled();
					return findStackErrors(results, tMonitor);
				}
			};

		List<List<StackErrorRow>> results = Collections.emptyList();
		try {
			results =
				ParallelDecompiler.decompileFunctions(callback, currentProgram, selection, monitor);
		}
		finally {
			callback.dispose();
			monitor.checkCancelled();
		}

		TableChooserDialog tableDialog =
			createTableChooserDialog(currentProgram.getName() + " problematic stack writes", null);
		configureTableColumns(tableDialog);

		boolean foundSomething = false;
		for (List<StackErrorRow> list : results) {
			for (StackErrorRow row : list) {
				tableDialog.add(row);
				foundSomething = true;
			}
		}
		if (!foundSomething) {
			popup("No problematic writes found");
			return;
		}
		tableDialog.show();
	}

	private List<StackErrorRow> findStackErrors(DecompileResults results, TaskMonitor tMonitor)
			throws CancelledException {

		List<StackErrorRow> rows = new ArrayList<>();
		HighFunction highFunction = results.getHighFunction();
		if (highFunction == null) {
			return rows;
		}
		AddressSetView body = results.getFunction().getBody();
		AddressSpace addrSpace = body.getMinAddress().getAddressSpace();
		Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
		while (ops.hasNext()) {
			tMonitor.checkCancelled();
			PcodeOp op = ops.next();
			if (op.getOpcode() != PcodeOp.COPY) {
				continue;
			}
			if (!op.getOutput().getAddress().isStackAddress()) {
				continue;
			}
			Varnode input = op.getInput(0);
			if (!input.isConstant()) {
				continue;
			}
			try {
				Address addr = addrSpace.getAddress(input.getOffset());
				if (body.contains(addr)) {
					rows.add(new StackErrorRow(results.getFunction(), op.getSeqnum().getTarget(),
						input.getOffset()));
				}
			}
			catch (AddressOutOfBoundsException e) {
				//this is can happen when the constant is an encoding of a floating
				//point value.
				continue;
			}
		}
		return rows;
	}

	class StackErrorConfigurer implements DecompileConfigurer {
		private Program p;

		public StackErrorConfigurer(Program prog) {
			p = prog;
		}

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(false);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("normalize");
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(p);
			decompiler.setOptions(opts);
		}
	}

	/**
	 * Table stuff
	 */

	static class StackErrorRow implements AddressableRowObject {
		private Function func;
		private Address errorAddress;
		private long value;

		public StackErrorRow(Function func, Address errorAddress, long value) {
			this.func = func;
			this.errorAddress = errorAddress;
			this.value = value;
		}

		public Function getFunction() {
			return func;
		}

		public long getValue() {
			return value;
		}

		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();
			sb.append(func.getName());
			sb.append(" error address: ");
			sb.append(errorAddress.toString());
			sb.append(", error value: ");
			sb.append(Long.toUnsignedString(value, 16));
			return sb.toString();
		}

		@Override
		public Address getAddress() {
			return errorAddress;
		}

	}

	private void configureTableColumns(TableChooserDialog dialog) {

		StringColumnDisplay functionNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Function Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((StackErrorRow) rowObject).getFunction().getName();
			}
		};

		ColumnDisplay<String> errorValueColumn = new AbstractComparableColumnDisplay<>() {

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				long errorVal = ((StackErrorRow) rowObject).getValue();
				int size = rowObject.getAddress().getAddressSpace().getSize() / 4;
				return String.format("0x%0" + size + "x", errorVal);
			}

			@Override
			public String getColumnName() {
				return "Value";
			}
		};

		dialog.addCustomColumn(functionNameColumn);
		dialog.addCustomColumn(errorValueColumn);
	}

}
