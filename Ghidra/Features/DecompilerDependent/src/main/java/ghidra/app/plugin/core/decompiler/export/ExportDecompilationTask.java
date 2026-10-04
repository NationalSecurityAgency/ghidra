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
package ghidra.app.plugin.core.decompiler.export;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ExportDecompilationTask extends Task {

	private final Program currentProgram;
	private final Function currentFunction;
	private final File outputDirectory;

	public ExportDecompilationTask(String title, Program program, File outputDirectory) {
		super(title);
		this.currentProgram = program;
		this.currentFunction = null;
		this.outputDirectory = outputDirectory;
	}

	public ExportDecompilationTask(String title, Program program, Function function,
			File outputDirectory) {
		super(title);
		this.currentProgram = program;
		this.currentFunction = function;
		this.outputDirectory = outputDirectory;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		PcodeExporter ex;
		try {
			ex = new PcodeExporter(outputDirectory.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
			return;
		}
		//ex.getDatabase().addExport(ex.LANGUAGE, "PCODE");
		ex.getDatabase().addExport(ex.PROGRAM_FILE, currentProgram.toString());

		ExportDecompilerConfigurer configurer = new ExportDecompilerConfigurer();

		DecompilerCallback<ExportableDecompileResults> callback =
			new DecompilerCallback<>(currentProgram, configurer) {

				// This could be done better, when results are available, other decompiler
				// results will stall.
				@Override
				public synchronized ExportableDecompileResults process(DecompileResults results,
						TaskMonitor tMonitor) throws Exception {
					ExportableDecompileResults rx = (ExportableDecompileResults) results;
					rx.processDoc(ex);
					return rx;
				}

				@Override
				public ExportableDecompileResults process(Function f, TaskMonitor monitor)
						throws Exception {
					if (monitor.isCancelled()) {
						return null;
					}

					ExportDecompInterface decompiler = new ExportDecompInterface();
					configurer.configure(decompiler);
					decompiler.openProgram(f.getProgram());
					ExportableDecompileResults decompileResults;

					monitor.setMessage("Decompiling " + f.getName());
					decompileResults = decompiler.decompileFunction(f, 10, monitor);

					ExportableDecompileResults r = process(decompileResults, monitor);
					return r;

				}

			};

		Set<Function> toProcess = new HashSet<Function>();
		if (currentFunction != null) {
			toProcess.add(currentFunction);
		}
		else {
			currentProgram.getFunctionManager().getFunctions(true).forEach(f -> {
				toProcess.add(f);
			});
			//currentProgram.getFunctionManager().getExternalFunctions().forEach(f -> {
			//	toProcess.add(f);
			//});
		}

		List<Function> toProcessList = new ArrayList<>(toProcess);
		Collections.sort(toProcessList,
			Comparator.<Function> comparingLong(f -> f.getBody().getNumAddresses()).reversed());

		monitor.initialize(toProcess.size());

		// dump defined data once
		ex.exportDefinedData(currentProgram);
		ex.exportRegisterInfo(currentProgram);
		ex.exportAddressSpaces(currentProgram);
		ex.exportMnemonics(currentProgram);

		try {
			ParallelDecompiler.decompileFunctions(callback, toProcessList, monitor);
		}
		catch (InterruptedException e) {
			throw new CancelledException();
		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
			return;
		}

		// System.out.println("Done producing");

		ex.externalFunctionParameters(currentProgram);
		ex.processVTables(currentProgram);
		// waiting until the end to write all datatypes TYPE_ may not save much time.
		// It could save time if the structures are complicated, so constantly
		// traversing
		// structure references all over again every 50 functions. Might not be worth
		// it.
		try {
			ex.writeFacts(true);
			ex.writeDebug();
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
			return;
		}
	}

}
