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
package ghidra.app.util.importer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Utility methods to do imports automatically (without requiring user interaction).
 */
public final class AutoImporter {
	private AutoImporter() {
		// service class; cannot instantiate
	}

	public static Program importByUsingBestGuess(File file, DomainFolder programFolder,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		List<Program> programs = importFresh(file, programFolder, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static Program importByUsingBestGuess(ByteProvider provider, DomainFolder programFolder,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		List<Program> programs = importFresh(provider, programFolder, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static Program importByUsingSpecificLoaderClass(File file, DomainFolder programFolder,
			Class<? extends Loader> loaderClass, List<Pair<String, String>> loaderArgs,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		SingleLoaderFilter loaderFilter = new SingleLoaderFilter(loaderClass, loaderArgs);
		List<Program> programs = importFresh(file, programFolder, consumer, messageLog, monitor,
			loaderFilter, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED, null,
			new LoaderArgsOptionChooser(loaderFilter),
			MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static Program importByLookingForLcs(File file, DomainFolder programFolder,
			Language language, CompilerSpec compilerSpec, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException {
		List<Program> programs = importFresh(file, programFolder, consumer, messageLog, monitor,
			LoaderService.ACCEPT_ALL, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static Program importByUsingSpecificLoaderClassAndLcs(File file,
			DomainFolder programFolder, Class<? extends Loader> loaderClass,
			List<Pair<String, String>> loaderArgs, Language language, CompilerSpec compilerSpec,
			Object consumer, MessageLog messageLog, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		SingleLoaderFilter loaderFilter = new SingleLoaderFilter(loaderClass, loaderArgs);
		List<Program> programs = importFresh(file, programFolder, consumer, messageLog, monitor,
			loaderFilter, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			new LoaderArgsOptionChooser(loaderFilter),
			MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	private static final Predicate<Loader> BINARY_LOADER =
		new SingleLoaderFilter(BinaryLoader.class);

	public static Program importAsBinary(File file, DomainFolder programFolder, Language language,
			CompilerSpec compilerSpec, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException {
		List<Program> programs = importFresh(file, programFolder, consumer, messageLog, monitor,
			BINARY_LOADER, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static Program importAsBinary(ByteProvider bytes, DomainFolder programFolder,
			Language language, CompilerSpec compilerSpec, Object consumer, MessageLog messageLog,
			TaskMonitor monitor) throws IOException, CancelledException, DuplicateNameException,
			InvalidNameException, VersionException {
		List<Program> programs = importFresh(bytes, programFolder, consumer, messageLog, monitor,
			BINARY_LOADER, new LcsHintLoadSpecChooser(language, compilerSpec), null,
			OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ONE_PROGRAM_OR_NULL);
		if (programs != null && programs.size() == 1) {
			return programs.get(0);
		}
		return null;
	}

	public static List<Program> importFresh(File file, DomainFolder programFolder, Object consumer,
			MessageLog messageLog, TaskMonitor monitor, Predicate<Loader> loaderFilter,
			LoadSpecChooser loadSpecChooser, String programNameOverride,
			OptionChooser optionChooser, MultipleProgramsStrategy multipleProgramsStrategy)
			throws IOException, CancelledException, DuplicateNameException, InvalidNameException,
			VersionException {
		if (file == null) {
			return null;
		}

		try (ByteProvider provider = new RandomAccessByteProvider(file)) {
			return importFresh(provider, programFolder, consumer, messageLog, monitor, loaderFilter,
				loadSpecChooser, programNameOverride, optionChooser, multipleProgramsStrategy);
		}
	}

	public static List<Program> importFresh(ByteProvider provider, DomainFolder programFolder,
			Object consumer, MessageLog messageLog, TaskMonitor monitor,
			Predicate<Loader> loaderFilter, LoadSpecChooser loadSpecChooser,
			String programNameOverride, OptionChooser optionChooser,
			MultipleProgramsStrategy multipleProgramsStrategy) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		if (provider == null) {
			return null;
		}

		// Get the load spec
		LoadSpec loadSpec = getLoadSpec(loaderFilter, loadSpecChooser, provider);
		if (loadSpec == null) {
			return null;
		}

		// Get the program name
		String programName = loadSpec.getLoader().getPreferredFileName(provider);
		if (programNameOverride != null) {
			programName = programNameOverride;
		}

		// Collect options
		LanguageCompilerSpecPair languageCompilerSpecPair = loadSpec.getLanguageCompilerSpec();
		AddressFactory addrFactory = null;// Address type options not permitted if null
		if (languageCompilerSpecPair != null) {
			// It is assumed that if languageCompilerSpecPair exists, then language will be found
			addrFactory = DefaultLanguageService.getLanguageService().getLanguage(
				languageCompilerSpecPair.languageID).getAddressFactory();
		}
		List<Option> loaderOptions = optionChooser.choose(
			loadSpec.getLoader().getDefaultOptions(provider, loadSpec, null, false), addrFactory);
		if (loaderOptions == null) {
			return null;
		}

		// Import program
		List<DomainObject> domainObjects = loadSpec.getLoader().load(provider, programName,
			programFolder, loadSpec, loaderOptions, messageLog, consumer, monitor);

		return multipleProgramsStrategy.handlePrograms(getPrograms(domainObjects), consumer);
	}

	private static LoadSpec getLoadSpec(Predicate<Loader> loaderFilter,
			LoadSpecChooser loadSpecChooser, ByteProvider provider) {
		LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(provider, loaderFilter);

		LoadSpec loadSpec = loadSpecChooser.choose(loaderMap);
		if (loadSpec != null) {
			return loadSpec;
		}

		File f = provider.getFile();
		String name = f != null ? f.getAbsolutePath() : provider.getName();
		Msg.info(AutoImporter.class, "No load spec found for import file: " + name);
		return null;
	}

	private static List<Program> getPrograms(List<DomainObject> domainObjects) {
		List<Program> programs = new ArrayList<Program>();
		for (DomainObject domainObject : domainObjects) {
			if (domainObject instanceof Program) {
				programs.add((Program) domainObject);
			}
		}

		return programs;
	}
}
