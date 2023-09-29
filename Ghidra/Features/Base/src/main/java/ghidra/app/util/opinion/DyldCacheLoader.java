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

	/** Loader option to fixup slide pointers */
	static final String FIXUP_SLIDE_POINTERS_OPTION_NAME = "Fixup slide pointers";

	/** Default value for loader option to fixup slide pointers */
	static final boolean FIXUP_SLIDE_POINTERS_OPTION_DEFAULT = true;

	/** Loader option to mark up slide pointers */
	static final String MARKUP_SLIDE_POINTERS_OPTION_NAME = "Markup slide pointers";

	/** Default value for loader option to mark up slide pointers */
	static final boolean MARKUP_SLIDE_POINTERS_OPTION_DEFAULT = true;

	/** Loader option to add slide pointers to relocation table */
	static final String ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME =
		"Add slide pointers to relocation table";

	/** Default value for loader option to add slide pointers to relocation table */
	static final boolean ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT = false;

	/** Loader option to process local symbols */
	static final String PROCESS_LOCAL_SYMBOLS_OPTION_NAME = "Process local symbols";

	/** Default value for loader option to process local symbols */
	static final boolean PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT = true;

	/** Loader option to mark up symbols */
	static final String MARKUP_LOCAL_SYMBOLS_OPTION_NAME = "Markup local symbol nlists";

	/** Default value for loader option to mark up symbols */
	static final boolean MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT = false;

	/** Loader option to process individual dylib's memory */
	static final String PROCESS_DYLIB_MEMORY_OPTION_NAME = "Process dylib memory";

	/** Loader option to process individual dylib's memory */
	static final boolean PROCESS_DYLIB_MEMORY_OPTION_DEFAULT = true;

	/** Loader option to process dylib symbols */
	static final String PROCESS_DYLIB_SYMBOLS_OPTION_NAME = "Process dylib symbols";

	/** Default value for loader option to process dylib symbols */
	static final boolean PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT = true;

	/** Loader option to process dylib exports */
	static final String PROCESS_DYLIB_EXPORTS_OPTION_NAME = "Process dylib exports";

	/** Default value for loader option to process dylib exports */
	static final boolean PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT = true;

	/** Loader option to mark up dylib load command data */
	static final String MARKUP_DYLIB_LC_DATA_OPTION_NAME = "Markup dylib load command data";

	/** Default value for loader option to mark up dylib load command data */
	static final boolean MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT = false;

	/** Loader option to process libobjc */
	static final String PROCESS_DYLIB_LIBOBJC_OPTION_NAME = "Process libobjc";

	/** Default value for loader option to process libobjc */
	static final boolean PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT = true;

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
			list.add(new Option(FIXUP_SLIDE_POINTERS_OPTION_NAME,
				FIXUP_SLIDE_POINTERS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-fixupSlidePointers"));
			list.add(
				new Option(MARKUP_SLIDE_POINTERS_OPTION_NAME, MARKUP_SLIDE_POINTERS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-markupSlidePointers"));
			list.add(new Option(ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME,
				ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-addSlidePointerRelocations"));
			list.add(
				new Option(PROCESS_LOCAL_SYMBOLS_OPTION_NAME, PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processLocalSymbols"));
			list.add(
				new Option(MARKUP_LOCAL_SYMBOLS_OPTION_NAME, MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-markupLocalSymbols"));
			list.add(
				new Option(PROCESS_DYLIB_MEMORY_OPTION_NAME, PROCESS_DYLIB_MEMORY_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processDylibMemory"));
			list.add(
				new Option(PROCESS_DYLIB_SYMBOLS_OPTION_NAME, PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processDylibSymbols"));
			list.add(
				new Option(PROCESS_DYLIB_EXPORTS_OPTION_NAME, PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processDylibExports"));
			list.add(new Option(MARKUP_DYLIB_LC_DATA_OPTION_NAME,
				MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-markupDylibLoadCommandData"));
			list.add(
				new Option(PROCESS_DYLIB_LIBOBJC_OPTION_NAME, PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT,
					Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-processLibobjc"));
		}
		return list;
	}

	private DyldCacheOptions getDyldCacheOptions(List<Option> options) {
		boolean fixupSlidePointers = OptionUtils.getOption(FIXUP_SLIDE_POINTERS_OPTION_NAME,
			options, FIXUP_SLIDE_POINTERS_OPTION_DEFAULT);
		boolean markupSlidePointers = OptionUtils.getOption(MARKUP_SLIDE_POINTERS_OPTION_NAME,
			options, MARKUP_SLIDE_POINTERS_OPTION_DEFAULT);
		boolean addSlidePointerRelocations =
			OptionUtils.getOption(ADD_SLIDE_POINTER_RELOCATIONS_OPTION_NAME, options,
				ADD_SLIDE_POINTERS_RELOCATIONS_OPTION_DEFAULT);
		boolean processLocalSymbols = OptionUtils.getOption(PROCESS_LOCAL_SYMBOLS_OPTION_NAME,
			options, PROCESS_LOCAL_SYMBOLS_OPTION_DEFAULT);
		boolean markupLocalSymbols = OptionUtils.getOption(MARKUP_LOCAL_SYMBOLS_OPTION_NAME,
			options, MARKUP_LOCAL_SYMBOLS_OPTION_DEFAULT);
		boolean processDylibMemory = OptionUtils.getOption(PROCESS_DYLIB_MEMORY_OPTION_NAME,
			options, PROCESS_DYLIB_MEMORY_OPTION_DEFAULT);
		boolean processDylibSymbols = OptionUtils.getOption(PROCESS_DYLIB_SYMBOLS_OPTION_NAME,
			options, PROCESS_DYLIB_SYMBOLS_OPTION_DEFAULT);
		boolean processDylibExports = OptionUtils.getOption(PROCESS_DYLIB_EXPORTS_OPTION_NAME,
			options, PROCESS_DYLIB_EXPORTS_OPTION_DEFAULT);
		boolean markupDylibLoadCommandData = OptionUtils.getOption(MARKUP_DYLIB_LC_DATA_OPTION_NAME,
			options, MARKUP_DYLIB_LC_DATA_OPTION_DEFAULT);
		boolean processLibobjc = OptionUtils.getOption(PROCESS_DYLIB_LIBOBJC_OPTION_NAME,
			options, PROCESS_DYLIB_LIBOBJC_OPTION_DEFAULT);
		return new DyldCacheOptions(fixupSlidePointers, markupSlidePointers,
			addSlidePointerRelocations, processLocalSymbols, markupLocalSymbols,
			processDylibMemory, processDylibSymbols, processDylibExports,
			markupDylibLoadCommandData, processLibobjc);
	}

	@Override
	public String getName() {
		return DYLD_CACHE_NAME;
	}
}
