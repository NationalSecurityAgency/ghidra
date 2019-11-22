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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ELFExternalSymbolResolver;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing executable and linking files (ELF).
 */
public class ElfLoader extends AbstractLibrarySupportLoader {

	public final static String ELF_NAME = "Executable and Linking Format (ELF)";

	public final static String ELF_ENTRY_FUNCTION_NAME = "entry";

	public final static String ELF_FILE_TYPE_PROPERTY = "ELF File Type";
	public final static String ELF_ORIGINAL_IMAGE_BASE_PROPERTY = "ELF Original Image Base";
	public final static String ELF_PRELINKED_PROPERTY = "ELF Prelinked";

	public final static String ELF_REQUIRED_LIBRARY_PROPERTY_PREFIX = "ELF Required Library ["; // followed by "#]"
	public final static String ELF_SOURCE_FILE_PROPERTY_PREFIX = "ELF Source File ["; // followed by "#]"

	/**
	 * Getter for the {@link #ELF_ORIGINAL_IMAGE_BASE_PROPERTY} property.
	 * 
	 * @param program Ghidra program that has the property to get
	 * @return Long value of the original image base, or null if the property is not present
	 */
	public static Long getElfOriginalImageBase(Program program) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		String oibStr = props.getString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, null);
		return (oibStr != null) ? NumericUtilities.parseHexLong(oibStr) : null;
	}

	public ElfLoader() {
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {

		// NOTE: add-to-program is not supported

		List<Option> options =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);

		try {
			ElfLoaderOptionsFactory.addOptions(options, provider, loadSpec);
		}
		catch (Exception e) {
			Msg.error(this, "Error while generating Elf import options", e);
			// ignore here, will catch later
		}

		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			String validationErrorStr = ElfLoaderOptionsFactory.validateOptions(loadSpec, options);
			if (validationErrorStr != null) {
				return validationErrorStr;
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			// TODO: Why do we convey image base to loader ?  This will be managed by each loader !
			List<QueryResult> results =
				QueryOpinionService.query(getName(), elf.getMachineName(), elf.getFlags());
			for (QueryResult result : results) {
				boolean add = true;
				// Some languages are defined with sizes smaller than 32
				if (elf.is32Bit() && result.pair.getLanguageDescription().getSize() > 32) {
					add = false;
				}
				if (elf.is64Bit() && result.pair.getLanguageDescription().getSize() <= 32) {
					add = false;
				}
				if (elf.isLittleEndian() &&
					result.pair.getLanguageDescription().getEndian() != Endian.LITTLE) {
					add = false;
				}
				if (elf.isBigEndian() &&
					result.pair.getLanguageDescription().getEndian() != Endian.BIG) {
					add = false;
				}
				if (add) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}
		catch (ElfException e) {
			// not a problem, it's not an elf
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			ElfHeader elf = ElfHeader.createElfHeader(factory, provider);
			ElfProgramBuilder.loadElf(elf, program, options, log, monitor);
		}
		catch (ElfException e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	protected void postLoadProgramFixups(List<Program> importedPrograms, DomainFolder importFolder,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		super.postLoadProgramFixups(importedPrograms, importFolder, options, messageLog, monitor);

		if (OptionUtils.getBooleanOptionValue(
			ElfLoaderOptionsFactory.RESOLVE_EXTERNAL_SYMBOLS_OPTION_NAME, options,
			ElfLoaderOptionsFactory.RESOLVE_EXTERNAL_SYMBOLS_DEFAULT)) {
			for (Program importedProgram : importedPrograms) {
				ELFExternalSymbolResolver.fixUnresolvedExternalSymbols(importedProgram, true,
					messageLog, monitor);
			}
		}
	}

	@Override
	public String getName() {
		return ELF_NAME;
	}
}
