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
public class DyldCacheLoader extends AbstractLibrarySupportLoader {

	public final static String DYLD_CACHE_NAME = "DYLD Cache";

	/** Loader option to process symbols*/
	static final String PROCESS_SYMBOLS_OPTION_NAME = "Process symbols";

	/** Default value for loader option to process symbols */
	static final boolean PROCESS_SYMBOLS_OPTION_DEFAULT = true;

	/** Loader option to add relocation entries for chained fixups */
	static final String ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME =
		"Add relocation entries for chained fixups";

	/** Default value for loader option to add chained fixups relocation entries */
	static final boolean ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT = false;

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
				shouldProcessSymbols(options), shouldAddChainedFixupsRelocations(options), log,
				monitor);
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
			list.add(new Option(PROCESS_SYMBOLS_OPTION_NAME, PROCESS_SYMBOLS_OPTION_DEFAULT,
				Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processSymbols"));
			list.add(new Option(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME,
				ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-addChainedFixupsRelocations"));
		}
		return list;
	}

	private boolean shouldProcessSymbols(List<Option> options) {
		return OptionUtils.getOption(PROCESS_SYMBOLS_OPTION_NAME, options,
			PROCESS_SYMBOLS_OPTION_DEFAULT);
	}

	private boolean shouldAddChainedFixupsRelocations(List<Option> options) {
		return OptionUtils.getOption(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME, options,
			ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT);
	}

	@Override
	public String getName() {
		return DYLD_CACHE_NAME;
	}
}
