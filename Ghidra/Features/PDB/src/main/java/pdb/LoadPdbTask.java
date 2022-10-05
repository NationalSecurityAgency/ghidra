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
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.plugin.core.analysis.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class LoadPdbTask extends Task {
	private File pdbFile;
	private DataTypeManagerService service;
	private final Program program;
	private final boolean useMsDiaParser;
	private final PdbApplicatorControl control; // PDB Universal Parser only
	private String resultMessages;
	private Exception resultException;

	LoadPdbTask(Program program, File pdbFile, boolean useMsDiaParser, PdbApplicatorControl control,
			DataTypeManagerService service) {
		super("Load PDB", true, false, true, true);
		this.program = program;
		this.pdbFile = pdbFile;
		this.useMsDiaParser = useMsDiaParser;
		this.control = control;
		this.service = service;
	}

	@Override
	public void run(TaskMonitor monitor) {

		WrappingTaskMonitor wrappedMonitor = new WrappingTaskMonitor(monitor) {
			@Override
			public void initialize(long max) {
				// don't let called clients change our monitor type; we don't show progress
			}
		};

		MessageLog log = new MessageLog();
		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDB";
			}

			@Override
			public boolean analysisWorkerCallback(Program currentProgram, Object workerContext,
					TaskMonitor currentMonitor) throws CancelledException {

				try {
					if (useMsDiaParser) {
						if (!parseWithMsDiaParser(log, wrappedMonitor)) {
							return false;
						}
					}
					else if (!parseWithNewParser(log, wrappedMonitor)) {
						return false;
					}
					scheduleAdditionalAnalysis();
				}
				catch (IOException e) {
					log.appendMsg("PDB IO Error: " + e.getMessage());
				}
				return false;
			}
		};

		try {
			AutoAnalysisManager.getAnalysisManager(program)
					.scheduleWorker(worker, null, true, wrappedMonitor);
		}
		catch (InterruptedException | CancelledException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			resultException = e;
		}
		if (log.hasMessages()) {
			resultMessages = log.toString();
		}

	}

	String getResultMessages() {
		return resultMessages;
	}

	Exception getResultException() {
		return resultException;
	}

	private boolean parseWithMsDiaParser(MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		PdbParser parser = new PdbParser(pdbFile, program, service, true, true, monitor);
		try {
			parser.parse();
			parser.openDataTypeArchives();
			parser.applyTo(log);
			return true;
		}
		catch (PdbException | DuplicateIdException e) {
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	private boolean parseWithNewParser(MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {

		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions(); // use defaults

		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();

		pdbApplicatorOptions.setProcessingControl(control);

		try (AbstractPdb pdb = ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser.parse(
			pdbFile.getAbsolutePath(), pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			DefaultPdbApplicator applicator =
				new DefaultPdbApplicator(pdb);
			applicator.applyTo(program, program.getDataTypeManager(), program.getImageBase(),
				pdbApplicatorOptions, log);

			return true;
		}
		catch (ghidra.app.util.bin.format.pdb2.pdbreader.PdbException e) {
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	// We need to kick off any byte analyzers (like getting import symbols), as they typically
	// won't get kicked off by our loading of the PDB.
	private void scheduleAdditionalAnalysis() {

		AddressSetView addrs = program.getMemory();
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		Options analysisProperties = program.getOptions(Program.ANALYSIS_PROPERTIES);

		//other planned analysis here.

		scheduleDemangler(manager, analysisProperties, addrs);
	}

	private void scheduleDemangler(AutoAnalysisManager manager, Options analysisProperties,
			AddressSetView addrs) {
		MicrosoftDemanglerAnalyzer demanglerAnalyzer = new MicrosoftDemanglerAnalyzer();
		String analyzerName = demanglerAnalyzer.getName();
		String valueAsString = analysisProperties.getValueAsString(analyzerName);

		// Only schedule analyzer if enabled
		if (!Boolean.parseBoolean(valueAsString)) {
			return;
		}
		manager.scheduleOneTimeAnalysis(demanglerAnalyzer, addrs);
	}

}
