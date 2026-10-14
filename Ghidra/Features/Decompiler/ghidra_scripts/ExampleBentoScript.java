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

import java.awt.Color;
import java.util.*;
import java.util.function.Consumer;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.bento.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;

public class ExampleBentoScript extends GhidraScript {

	// This script is essentially identical to the CompareFunctionSizesScript, but adds the
	// option of plotting some subset of the table entries as a "Bento" display.

	static class ExampleBentoExecutor implements TableChooserExecutor {

		private BentoService service;
		private Program program;

		public ExampleBentoExecutor(PluginTool tool, Program program) {
			service = tool.getService(BentoService.class);
			this.program = program;
		}

		@Override
		public String getButtonName() {
			return "Plot";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			return false;
		}

		@SuppressWarnings("hiding")
		@Override
		public boolean executeInBulk(List<AddressableRowObject> rowObjects,
				List<AddressableRowObject> deleted, TaskMonitor monitor) {
			List<BentoBox> boxes = new ArrayList<>();
			for (AddressableRowObject row : rowObjects) {
				if (row instanceof ExampleRow src) {
					BoundedObject x = new BoundedObject(src.getNumInstructions(),
						src.getNumInstructions() + 100);
					BoundedObject y = new FunctionBoundedObject(src.getFunction());
					BoundedObject z = new BoundedObject(src.getNumHighOps(),
						src.getNumHighOps() + 40);
					List<BoundedObject> objects = new ArrayList<>();
					objects.add(x);
					objects.add(y);
					objects.add(z);
					BentoBox box = new BentoBox(src.getFunction().getName(), objects, Color.RED);
					boxes.add(box);
				}
			}
			BentoProvider provider = service.createProvider();
			provider.setBoxes(boxes);
			provider.setProgram(program);
			provider.setColumns(List.of("Inst", "Addr", "Op"));
			provider.setRadix(0, BentoRadix.HEX_UPPER);
			return false;
		}
	}

	static class ExampleRow implements AddressableRowObject {
		private int numInstructions;
		private int numHighOps;
		private double ratio;
		private Function func;

		public ExampleRow(Function f, int numInst, int numHigh) {
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

	@Override
	protected void run() throws Exception {

		if (isRunningHeadless()) {
			println("This script cannot be run headlessly");
			return;
		}

		ExampleBentoExecutor executor = new ExampleBentoExecutor(this.getState().getTool(), currentProgram);
		TableChooserDialog bentoDialog =
			createTableChooserDialog(currentProgram.getName() + " function sizes", executor);
		configureTableColumns(bentoDialog);
		bentoDialog.show();

		DecompilerCallback<ExampleRow> callback = new DecompilerCallback<>(
			currentProgram, new CompareFunctionSizesScriptConfigurer(currentProgram)) {

			@Override
			public ExampleRow process(DecompileResults results, TaskMonitor tMonitor)
					throws Exception {

				Listing listing = currentProgram.getListing();
				Function function = results.getFunction();
				InstructionIterator it = listing.getInstructions(function.getBody(), true);
				int numInstructions = IteratorUtils.size(it);

				// indicate failure of decompilation by having 0 high pcode ops
				int numHighOps = 0;
				HighFunction highFunction = results.getHighFunction();
				if (highFunction != null) {
					Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
					if (ops != null) {
						numHighOps = IteratorUtils.size(ops);
					}
				}
				return new ExampleRow(function, numInstructions, numHighOps);
			}
		};

		Consumer<ExampleRow> consumer = data -> bentoDialog.add(data);
		FunctionIterator it = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		ParallelDecompiler.decompileFunctions(callback, currentProgram, it, consumer, monitor);
		callback.dispose();
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


	interface RowEntries {
		void add(ExampleRow row);

		void setMessage(String message);

		void clear();
	}

	class TableEntryList implements RowEntries {

		private TableChooserDialog tDialog;

		public TableEntryList(TableChooserDialog dialog) {
			tDialog = dialog;
		}

		@Override
		public void add(ExampleRow row) {
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
				return ((ExampleRow) rowObject).getFunction().getName();
			}
		};

		ColumnDisplay<Integer> highOpsColumn = new AbstractComparableColumnDisplay<>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((ExampleRow) rowObject).getNumHighOps();
			}

			@Override
			public String getColumnName() {
				return "Num High Ops";
			}
		};

		ColumnDisplay<Integer> instructionColumn = new AbstractComparableColumnDisplay<>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((ExampleRow) rowObject).getNumInstructions();
			}

			@Override
			public String getColumnName() {
				return "Num Instructions";
			}
		};

		ColumnDisplay<Double> ratioColumn = new AbstractComparableColumnDisplay<>() {

			@Override
			public Double getColumnValue(AddressableRowObject rowObject) {
				return ((ExampleRow) rowObject).getRatio();
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
