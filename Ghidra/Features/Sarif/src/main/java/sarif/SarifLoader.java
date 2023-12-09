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
package sarif;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.SarifObject;
import sarif.managers.ProgramInfo;
import sarif.managers.ProgramSarifMgr;

public class SarifLoader extends AbstractProgramLoader {

	private static final String FILE_EXTENSION = SarifObject.SARIF ? ".sarif" : ".json";
	public final static String SARIF_SRC_NAME = "SARIF Input Format";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {

		List<LoadSpec> loadSpecs = new ArrayList<>();

		//
		// Unusual Code Alert!: the parse() method below uses Processor to
		// location processors
		// by name when reading SARIF. The Processor class is not fully
		// populated until the languages have been loaded.
		//
		getLanguageService();

		ParseResult result = parse(provider);

		ProgramInfo info = result.lastInfo;
		if (info == null) {
			return loadSpecs;
		}
		
		if (info.languageID != null) {// non-external language
			// got a language ID, good...
			try {
				LanguageDescription languageDescription =
					getLanguageService().getLanguageDescription(info.languageID);

				boolean preferred = false;
				if (info.compilerSpecID == null) {
					// no compiler spec ID, try to pick "default" (embedded
					// magic string!!! BAD)
					for (CompilerSpecDescription csd : languageDescription.getCompatibleCompilerSpecDescriptions()) {
						LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(
							languageDescription.getLanguageID(), csd.getCompilerSpecID());
						loadSpecs.add(new LoadSpec(this, 0, pair, preferred));
					}
				}
				else {
					// test existence; throw exception on failure
					languageDescription.getCompilerSpecDescriptionByID(info.compilerSpecID);
					// good, we know exactly what this is (make it preferred)
					LanguageCompilerSpecPair pair =
						new LanguageCompilerSpecPair(info.languageID, info.compilerSpecID);
					preferred = true;
					loadSpecs.add(new LoadSpec(this, 0, pair, preferred));
				}
			}
			catch (CompilerSpecNotFoundException | LanguageNotFoundException lnfe) {
				// ignore
				// should fall into loadSpecs.isEmpty() case below
			}

		}
		else if (info.processorName != null) {// external language
			// no ID, look by processor/possibly endian
			Integer size = extractSize(info.addressModel);
			Endian endian = Endian.toEndian(info.endian);
			ExternalLanguageCompilerSpecQuery broadQuery =
				new ExternalLanguageCompilerSpecQuery(info.processorName,
					info.getNormalizedExternalToolName(), endian, size, info.compilerSpecID);
			List<LanguageCompilerSpecPair> pairs =
				getLanguageService().getLanguageCompilerSpecPairs(broadQuery);

			if (!pairs.isEmpty()) {
				boolean preferred = false;
				if (pairs.size() == 1) {
					preferred = true;
				}
				for (LanguageCompilerSpecPair pair : pairs) {
					loadSpecs.add(new LoadSpec(this, 0, pair, preferred));
				}
			}
		}

		if (loadSpecs.isEmpty() && provider.getName().endsWith(FILE_EXTENSION)) {
			// just put 'em all in (give endianess preference)
			List<LanguageDescription> languageDescriptions =
				getLanguageService().getLanguageDescriptions(false);
			for (LanguageDescription languageDescription : languageDescriptions) {
				Collection<CompilerSpecDescription> compilerSpecDescriptions =
					languageDescription.getCompatibleCompilerSpecDescriptions();
				for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
					LanguageCompilerSpecPair pair =
						new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
							compilerSpecDescription.getCompilerSpecID());
					loadSpecs.add(new LoadSpec(this, 0, pair, false));
				}
			}
		}
		return loadSpecs;
	}

	private static Pattern ADDRESS_MODEL_PATTERN = Pattern.compile("(\\d+)-bit");

	private Integer extractSize(String addressModel) {
		if (addressModel != null) {
			Matcher matcher = ADDRESS_MODEL_PATTERN.matcher(addressModel);
			if (matcher.find()) {
				return Integer.parseInt(matcher.group(1));
			}
		}
		return null;
	}
	
	@Override
	public String getPreferredFileName(ByteProvider provider) {
		String name = provider.getName();
		if (name.toLowerCase().endsWith(FILE_EXTENSION)) {
			return name.substring(0, name.length() - FILE_EXTENSION.length());
		}
		return name;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName,
			Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {

		//throw new RuntimeException("SARIF importer supports only 'Add To Program'");
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec =
			importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

		ParseResult result = parse(provider);

		Address imageBase = null;
		if (result.lastInfo.imageBase != null) {
			imageBase = importerLanguage.getAddressFactory().getAddress(result.lastInfo.imageBase);
		}
		Program prog = createProgram(provider, programName, imageBase, getName(), importerLanguage,
			importerCompilerSpec, consumer);
		List<Loaded<Program>> loadedList =
			List.of(new Loaded<>(prog, programName, programFolderPath));
		boolean success = false;
		try {
			success = doImport(result.lastSarifMgr, options, log, prog, monitor, false);
			if (success) {
				createDefaultMemoryBlocks(prog, importerLanguage, log);
				return loadedList;
			}
			throw new LoadException("Failed to load");
		}
		finally {
			if (!success) {
				release(loadedList, consumer);
			}
		}
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		File file = provider.getFile();
		doImport(new ProgramSarifMgr(prog, file), options, log, prog, monitor, true);
	}

	private boolean doImportWork(final ProgramSarifMgr mgr, final List<Option> options,
			final MessageLog log, Program prog, TaskMonitor monitor,
			final boolean isAddToProgram) throws LoadException {
		boolean success = true;
		try {
			SarifProgramOptions sarifOptions = mgr.getOptions();
			sarifOptions.setOptions(options);
			sarifOptions.setAddToProgram(isAddToProgram);
			mgr.read(prog, monitor);
			success = true;
		}
		catch (Exception e) {
			String message = "(empty)";
			if (log != null && !"".equals(log.toString())) {
				message = log.toString();
			}
			Msg.warn(this, "SARIF import exception, log: " + message, e);
			throw new LoadException(e.getMessage());
		}
		return success;
	}

	private boolean doImport(final ProgramSarifMgr mgr, final List<Option> options,
			final MessageLog log, Program prog, TaskMonitor monitor, final boolean isAddToProgram)
			throws IOException {

		if (!AutoAnalysisManager.hasAutoAnalysisManager(prog)) {
			int txId = prog.startTransaction("SARIF Import");
			try {
				return doImportWork(mgr, options, log, prog, monitor, isAddToProgram);
			}
			finally {
				prog.endTransaction(txId, true);
			}
		}

		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(prog);
		try {
			return analysisMgr.scheduleWorker(new AnalysisWorker() {

				@Override
				public String getWorkerName() {
					return "SARIF Importer";
				}

				@Override
				public boolean analysisWorkerCallback(Program program, Object workerContext,
						TaskMonitor taskMonitor) throws Exception, CancelledException {
					return doImportWork(mgr, options, log, program, taskMonitor, isAddToProgram);
				}
			}, null, false, monitor);

		}
		catch (CancelledException e) {
			return false;
		}
		catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause instanceof IOException) {
				throw (IOException) cause;
			}
			throw new RuntimeException(e);
		}
		catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	private static class ParseResult {
		final ProgramSarifMgr lastSarifMgr;
		final ProgramInfo lastInfo;

		ParseResult(ProgramSarifMgr lastSarifMgr, ProgramInfo lastInfo) {
			this.lastSarifMgr = lastSarifMgr;
			this.lastInfo = lastInfo;
		}
	}

	private ParseResult parse(ByteProvider provider) {
		try {
			ProgramSarifMgr lastSarifMgr = new ProgramSarifMgr(provider);
			ProgramInfo lastInfo = lastSarifMgr.getProgramInfo();
			return new ParseResult(lastSarifMgr, lastInfo);
		}
		catch (Throwable e) {
			// This can happen during the import process when this loader attempts to load 
			// a non-SARIF file (there really should be 2 methods, a speculative version and 
			// a version that expects no exception)
			Msg.trace(this, "Unable to parse SARIF for " + provider.getName(), e);
			return new ParseResult(null, null);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		return new SarifProgramOptions().getOptions(loadIntoProgram);
	}

	@Override
	public String getName() {
		return SARIF_SRC_NAME;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		try {
			new SarifProgramOptions().setOptions(options);
		}
		catch (OptionException e) {
			return e.getMessage();
		}
		return null;
	}
}
