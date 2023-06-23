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

import ghidra.app.util.*;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.dyld.DyldArchitecture;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for DYLD shared cache files.
 */
public class DyldCacheLoader extends AbstractProgramWrapperLoader {

	public final static String DYLD_CACHE_NAME = "DYLD Cache";

	/** Loader option to process symbols */
	static final String PROCESS_LOCAL_SYMBOLS_OPTION_NAME = "Process local symbols";

	/** Default value for loader option to process symbols */
	static final boolean PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT = true;

	/** Loader option to process exports */
	static final String PROCESS_EXPORTS_OPTION_NAME = "Process exports";

	/** Default value for loader option to process exports */
	static final boolean PROCESS_EXPORTS_OPTION_DEFAULT = true;

	/** Loader option to mark up symbols */
	static final String MARKUP_LOCAL_SYMBOLS_OPTION_NAME = "Markup local symbol nlists (slow)";

	/** Default value for loader option to mark up symbols */
	static final boolean MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT = false;

	/** Loader option to process chained fixups */
	static final String PROCESS_CHAINED_FIXUPS_OPTION_NAME = "Process chained fixups";

	/** Default value for loader option to process chained fixups */
	static final boolean PROCESS_CHAINED_FIXUPS_OPTION_DEFAULT = true;

	/** Loader option to add chained fixups to relocation table */
	static final String ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME =
		"Add chained fixups to relocation table";

	/** Default value for loader option to add chained fixups to relocation table */
	static final boolean ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT = false;

	/** Loader option to mark up Mach-O load command data */
	static final String MARKUP_MACHO_LC_DATA_OPTION_NAME = "Markup Mach-O load command data (slow)";

	/** Default value for loader option to mark up Mach-O load command data */
	static final boolean MARKUP_MACHO_LC_DATA_OPTION_DEFAULT = false;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (!DyldCacheUtils.isDyldCache(provider)) {
			return loadSpecs;
		}

		try {
			DyldCacheHeader header = new DyldCacheHeader(new BinaryReader(provider, true));
			if (header.isSubcache()) {
				return loadSpecs;
			}
			DyldArchitecture architecture = header.getArchitecture();
			if (architecture != null) {
				List<QueryResult> results =
					QueryOpinionService.query(getName(), architecture.getProcessor(), null);
				for (QueryResult result : results) {
					loadSpecs.add(new LoadSpec(this, header.getBaseAddress(), result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, header.getBaseAddress(), true));
				}
			}
		}
		catch (IOException e) {
			// It's not what we expect, so don't consider it
		}
		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			DyldCacheProgramBuilder.buildProgram(program, provider,
				MemoryBlockUtils.createFileBytes(program, provider, monitor),
				getDyldCacheOptions(options), log, monitor);
		}
		catch (CancelledException e) {
			return;
		}
		catch (Exception e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		if (!loadIntoProgram) {
			list.add(
				new Option(PROCESS_LOCAL_SYMBOLS_OPTION_NAME, PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processLocalSymbols"));
			list.add(
				new Option(MARKUP_LOCAL_SYMBOLS_OPTION_NAME, MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-markupLocalSymbols"));
			list.add(
				new Option(PROCESS_EXPORTS_OPTION_NAME, PROCESS_EXPORTS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processExports"));
			list.add(new Option(PROCESS_CHAINED_FIXUPS_OPTION_NAME,
				PROCESS_CHAINED_FIXUPS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-processChainedFixups"));
			list.add(new Option(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME,
				ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-addChainedFixupsRelocations"));
			list.add(new Option(MARKUP_MACHO_LC_DATA_OPTION_NAME,
				MARKUP_MACHO_LC_DATA_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-markupMachoLoadCommandData"));
		}
		return list;
	}

	private DyldCacheOptions getDyldCacheOptions(List<Option> options) {
		boolean processLocalSymbols = OptionUtils.getOption(PROCESS_LOCAL_SYMBOLS_OPTION_NAME,
			options, PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT);
		boolean markupLocalSymbols = OptionUtils.getOption(MARKUP_LOCAL_SYMBOLS_OPTION_NAME,
			options, MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT);
		boolean processExports = OptionUtils.getOption(PROCESS_EXPORTS_OPTION_NAME,
			options, PROCESS_EXPORTS_OPTION_DEFAULT);
		boolean processChainedFixups = OptionUtils.getOption(PROCESS_CHAINED_FIXUPS_OPTION_NAME,
			options, PROCESS_CHAINED_FIXUPS_OPTION_DEFAULT);
		boolean addChainedFixupsRelocations =
			OptionUtils.getOption(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME, options,
				ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT);
		boolean markupMachoLoadCommandData = OptionUtils.getOption(MARKUP_MACHO_LC_DATA_OPTION_NAME,
			options, MARKUP_MACHO_LC_DATA_OPTION_DEFAULT);
		return new DyldCacheOptions(processLocalSymbols, markupLocalSymbols, processExports,
			processChainedFixups, addChainedFixupsRelocations, markupMachoLoadCommandData);
	}

	@Override
	public String getName() {
		return DYLD_CACHE_NAME;
	}
}
