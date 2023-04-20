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
package ghidra.app.plugin.core.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ExternalSymbolResolver;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link Analyzer} to link unresolved symbols
 * 
 * @see ExternalSymbolResolver
 */
public class ExternalSymbolResolverAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "External Symbol Resolver";
	private static final String DESCRIPTION =
		"Links unresolved external symbols to the first symbol found in the program's required libraries list (found in program properties).";

	/**
	 * Creates a new {@link ExternalSymbolResolverAnalyzer} 
	 */
	public ExternalSymbolResolverAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();

		// Do it before demangling
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		// This analyzer needs to look around the project for imported libraries
		if (program.getDomainFile().getParent() == null) {
			return false;
		}
		
		Options options = program.getOptions(Program.PROGRAM_INFO);
		String format = options.getString("Executable Format", null);
		return ElfLoader.ELF_NAME.equals(format) || MachoLoader.MACH_O_NAME.equals(format);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Object consumer = new Object();
		log = new MessageLog(); // For now, we don't want the analysis log spammed
		ProjectData projectData = program.getDomainFile().getParent().getProjectData();
		List<Loaded<Program>> loadedPrograms = new ArrayList<>();

		// Add program to list
		loadedPrograms.add(new Loaded<>(program, program.getName(),
			program.getDomainFile().getParent().getPathname()));

		// Add external libraries to list
		for (Library extLibrary : ExternalSymbolResolver.getLibrarySearchList(program)) {
			monitor.checkCancelled();
			String libPath = extLibrary.getAssociatedProgramPath();
			if (libPath == null) {
				continue;
			}

			DomainFile libDomainFile = projectData.getFile(libPath);
			if (libDomainFile == null) {
				log.appendMsg("Referenced external program not found: " + libPath);
				continue;
			}

			try {
				DomainObject libDomainObject =
					libDomainFile.getDomainObject(consumer, false, false, monitor);
				if (libDomainObject instanceof Program p) {
					loadedPrograms.add(new Loaded<>(p, libDomainFile.getName(),
						libDomainFile.getParent().getPathname()));
				}
				else {
					libDomainObject.release(consumer);
					log.appendMsg("Referenced external program is not a program: " + libPath);
				}
			}
			catch (IOException e) {
				log.appendMsg("Failed to open library dependency project file: " +
					libDomainFile.getPathname());
			}
			catch (VersionException e) {
				log.appendMsg(
					"Referenced external program requires updgrade, unable to consider symbols: " +
						libPath);
			}
		}

		// Resolve symbols
		try {
			ExternalSymbolResolver.fixUnresolvedExternalSymbols(loadedPrograms, false, log,
				monitor);
			return true;
		}
		catch (IOException e) {
			return false;
		}
		finally {
			for (int i = 1; i < loadedPrograms.size(); i++) {
				loadedPrograms.get(i).release(consumer);
			}
		}
	}
}
