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
package pdb;

import java.io.File;
import java.lang.reflect.InvocationTargetException;

import docking.DockingWindowManager;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.plugin.core.analysis.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class LoadPdbTask extends Task {
	private File pdbFile;
	private DataTypeManagerService service;
	private final Program program;

	LoadPdbTask(Program program, File pdbFile, DataTypeManagerService service) {
		super("Loading PDB...", true, false, false);
		this.program = program;
		this.pdbFile = pdbFile;
		this.service = service;
	}

	@Override
	public void run(final TaskMonitor monitor) {
		final MessageLog log = new MessageLog();

		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDB";
			}

			@Override
			public boolean analysisWorkerCallback(Program currentProgram, Object workerContext,
					TaskMonitor currentMonitor) throws Exception, CancelledException, PdbException {

				PdbParser parser =
					new PdbParser(pdbFile, program, service, true, currentMonitor);

				parser.parse();
				parser.openDataTypeArchives();
				parser.applyTo(log);

				analyzeSymbols(currentMonitor, log);
				return !monitor.isCancelled();
			}
		};

		boolean analyzed =
			program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false);
		if (analyzed) {
			Msg.showWarn(this, null, "PDB Warning",
				"Loading PDB after analysis has been performed will produce" +
					"\npoor results.  PDBs should be loaded prior to analysis or" +
					"\nautomatically during auto-analysis.");
		}

		try {
			AutoAnalysisManager.getAnalysisManager(program)
					.scheduleWorker(worker, null, true,
						monitor);
		}
		catch (InterruptedException | CancelledException e1) {
			// ignore
		}
		catch (InvocationTargetException e) {
			String message;

			Throwable t = e.getCause();

			if (t == null) {
				message = "Unknown cause";
			}
			else {
				message = t.getMessage();

				if (message == null) {
					message = t.toString();
				}
			}

			Msg.showError(getClass(), null, "Load PDB Failed", message, t);
		}

		if (log.hasMessages()) {
			MultiLineMessageDialog dialog = new MultiLineMessageDialog("Load PDB File",
				"There were warnings/errors loading the PDB file.", log.toString(),
				MultiLineMessageDialog.WARNING_MESSAGE, false);
			DockingWindowManager.showDialog(null, dialog);
		}
	}

	private void analyzeSymbols(TaskMonitor monitor, MessageLog log) {

		MicrosoftDemanglerAnalyzer demanglerAnalyzer = new MicrosoftDemanglerAnalyzer();
		String analyzerName = demanglerAnalyzer.getName();

		Options analysisProperties = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String defaultValueAsString = analysisProperties.getValueAsString(analyzerName);
		boolean doDemangle = true;
		if (defaultValueAsString != null) {
			doDemangle = Boolean.parseBoolean(defaultValueAsString);
		}

		if (doDemangle) {
			AddressSetView addrs = program.getMemory();
			monitor.initialize(addrs.getNumAddresses());
			try {
				demanglerAnalyzer.added(program, addrs, monitor, log);
			}
			catch (CancelledException e) {
				// Don't care about CancelledException
			}

		}
	}
}
