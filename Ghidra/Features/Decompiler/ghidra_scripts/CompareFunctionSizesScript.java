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
// Displays a table comparing the sizes of functions to the sizes of their decompilations.

// Use this script to help identify functions that are being decompiled incorrectly.  If you find
// a function with many instructions whose decompilation is quite short, there might be something fishy going on
// with the return value.
//
// Note: a value of -1.0 in the "Ratio" column indicates a failure during decompilation.

// @category Analysis 

import java.util.*;

import com.google.common.collect.Iterators;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class CompareFunctionSizesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (isRunningHeadless()) {
			printf("This script cannot be run headlessly.\n");
			return;
		}

		DecompilerCallback<FuncBodyData> callback = new DecompilerCallback<FuncBodyData>(
			currentProgram, new CompareFunctionSizesScriptConfigurer(currentProgram)) {

			@Override
			public FuncBodyData process(DecompileResults results, TaskMonitor tMonitor)
					throws Exception {
				InstructionIterator instIter = currentProgram.getListing().getInstructions(
					results.getFunction().getBody(), true);
				int numInstructions = Iterators.size(instIter);
				//indicate failure of decompilation by having 0 high pcode ops
				int numHighOps = 0;
				if (results.getHighFunction() != null &&
					results.getHighFunction().getPcodeOps() != null) {
					numHighOps = Iterators.size(results.getHighFunction().getPcodeOps());
				}
				return new FuncBodyData(results.getFunction(), numInstructions, numHighOps);
			}
		};

		Set<Function> funcsToDecompile = new HashSet<>();
		FunctionIterator fIter = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		Iterators.addAll(funcsToDecompile, fIter);

		if (funcsToDecompile.isEmpty()) {
			popup("No functions to decompile!");
			return;
		}

		List<FuncBodyData> funcBodyData = ParallelDecompiler.decompileFunctions(callback,
			currentProgram, funcsToDecompile, monitor);

		monitor.checkCanceled();

		TableChooserDialog tableDialog =
			createTableChooserDialog(currentProgram.getName() + " function sizes", null);
		configureTableColumns(tableDialog);

		tableDialog.show();
		for (FuncBodyData bodyData : funcBodyData) {
			tableDialog.add(bodyData);
		}
	}

	class CompareFunctionSizesScriptConfigurer implements DecompileConfigurer {
		private Program p;

		public CompareFunctionSizesScriptConfigurer(Program prog) {
			p = prog;
		}

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(false);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(p);
			decompiler.setOptions(opts);
		}
	}

	/**
	 * Table stuff
	 */

	static class FuncBodyData implements AddressableRowObject {
		private int numInstructions;
		private int numHighOps;
		private double ratio;
		private Function func;

		public FuncBodyData(Function f, int numInst, int numHigh) {
			func = f;
			numInstructions = numInst;
			numHighOps = numHigh;
			if (numHighOps == 0) {
				ratio = -1.0;
			}
			else {
				ratio = (numHighOps * 1.0) / numInstructions;
			}
		}

		public int getNumInstructions() {
			return numInstructions;
		}

		public int getNumHighOps() {
			return numHighOps;
		}

		public Function getFunction() {
			return func;
		}

		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();
			sb.append(func.getName());
			sb.append(" instructions: ");
			sb.append(Integer.toString(numInstructions));
			sb.append(", high ops: ");
			sb.append(Integer.toString(numHighOps));
			return sb.toString();
		}

		@Override
		public Address getAddress() {
			return func.getEntryPoint();
		}

		public double getRatio() {
			return ratio;
		}
	}

	interface RowEntries {
		void add(FuncBodyData row);

		void setMessage(String message);

		void clear();
	}

	class TableEntryList implements RowEntries {

		private TableChooserDialog tDialog;

		public TableEntryList(TableChooserDialog dialog) {
			tDialog = dialog;
		}

		@Override
		public void add(FuncBodyData row) {
			tDialog.add(row);

		}

		@Override
		public void setMessage(String message) {
			tDialog.setMessage(message);

		}

		@Override
		public void clear() {
			return;
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
				return ((FuncBodyData) rowObject).getFunction().getName();
			}
		};

		ColumnDisplay<Integer> highOpsColumn = new AbstractComparableColumnDisplay<Integer>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((FuncBodyData) rowObject).getNumHighOps();
			}

			@Override
			public String getColumnName() {
				return "Num High Ops";
			}
		};

		ColumnDisplay<Integer> instructionColumn = new AbstractComparableColumnDisplay<Integer>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((FuncBodyData) rowObject).getNumInstructions();
			}

			@Override
			public String getColumnName() {
				return "Num Instructions";
			}
		};

		ColumnDisplay<Double> ratioColumn = new AbstractComparableColumnDisplay<Double>() {

			@Override
			public Double getColumnValue(AddressableRowObject rowObject) {
				return ((FuncBodyData) rowObject).getRatio();
			}

			@Override
			public String getColumnName() {
				return "Ratio";
			}
		};
		dialog.addCustomColumn(functionNameColumn);
		dialog.addCustomColumn(highOpsColumn);
		dialog.addCustomColumn(instructionColumn);
		dialog.addCustomColumn(ratioColumn);
	}

}
