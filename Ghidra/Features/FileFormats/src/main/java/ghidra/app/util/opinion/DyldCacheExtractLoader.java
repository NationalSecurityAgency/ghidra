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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.ios.dyldcache.DyldCacheExtractor;
import ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for components extracted by Ghidra from a DYLD Cache
 */
public class DyldCacheExtractLoader extends MachoLoader {

	public final static String DYLD_CACHE_EXTRACT_NAME = "Extracted DYLD Component";

	static final String LIBOBJC_OPTION_NAME = "Add libobjc.dylib";
	static final boolean LIBOBJC_OPTION_DEFAULT = true;

	static final String AUTH_DATA_OPTION_NAME = "Add AUTH_DATA";
	static final boolean AUTH_DATA_OPTION_DEFAULT = false;

	static final String DIRTY_DATA_OPTION_NAME = "Add DIRTY_DATA";
	static final boolean DIRTY_DATA_OPTION_DEFAULT = false;

	static final String CONST_DATA_OPTION_NAME = "Add CONST_DATA";
	static final boolean CONST_DATA_OPTION_DEFAULT = true;

	static final String TEXT_STUBS_OPTION_NAME = "Add TEXT_STUBS";
	static final boolean TEXT_STUBS_OPTION_DEFAULT = true;

	static final String CONFIG_DATA_OPTION_NAME = "Add CONFIG_DATA";
	static final boolean CONFIG_DATA_OPTION_DEFAULT = false;

	static final String READ_ONLY_DATA_OPTION_NAME = "Add READ_ONLY_DATA";
	static final boolean READ_ONLY_DATA_OPTION_DEFAULT = true;

	static final String CONST_TPRO_DATA_OPTION_NAME = "Add CONST_TPRO_DATA";
	static final boolean CONST_TPRO_DATA_OPTION_DEFAULT = false;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (provider.length() >= DyldCacheExtractor.FOOTER_V1.length) {
			if (Arrays.equals(DyldCacheExtractor.FOOTER_V1,
				provider.readBytes(provider.length() - DyldCacheExtractor.FOOTER_V1.length,
					DyldCacheExtractor.FOOTER_V1.length))) {
				return super.findSupportedLoadSpecs(provider);
			}
		}
		return List.of();
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
			MachoExtractProgramBuilder.buildProgram(program, provider, fileBytes, log, monitor);
			addOptionalComponents(program, options, log, monitor);
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		load(provider, loadSpec, options, program, monitor, messageLog);
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		return DYLD_CACHE_EXTRACT_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public String getName() {
		return DYLD_CACHE_EXTRACT_NAME;
	}

	@Override
	public int getTierPriority() {
		return 49; // Higher priority than MachoLoader
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(LIBOBJC_OPTION_NAME, !loadIntoProgram && LIBOBJC_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-libobjc"));
		list.add(new Option(AUTH_DATA_OPTION_NAME, !loadIntoProgram && AUTH_DATA_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-authData"));
		list.add(new Option(DIRTY_DATA_OPTION_NAME, !loadIntoProgram && DIRTY_DATA_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-dirtyData"));
		list.add(new Option(CONST_DATA_OPTION_NAME, !loadIntoProgram && CONST_DATA_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-constData"));
		list.add(new Option(TEXT_STUBS_OPTION_NAME, !loadIntoProgram && TEXT_STUBS_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-textStubs"));
		list.add(new Option(CONFIG_DATA_OPTION_NAME, !loadIntoProgram && CONFIG_DATA_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-configData"));
		list.add(new Option(READ_ONLY_DATA_OPTION_NAME,
			!loadIntoProgram && READ_ONLY_DATA_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-readOnlyData"));
		list.add(new Option(CONST_TPRO_DATA_OPTION_NAME,
			!loadIntoProgram && CONST_TPRO_DATA_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-constTproData"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(LIBOBJC_OPTION_NAME) || name.equals(AUTH_DATA_OPTION_NAME) ||
					name.equals(DIRTY_DATA_OPTION_NAME) || name.equals(CONST_DATA_OPTION_NAME) ||
					name.equals(TEXT_STUBS_OPTION_NAME) || name.equals(CONFIG_DATA_OPTION_NAME) ||
					name.equals(READ_ONLY_DATA_OPTION_NAME) ||
					name.equals(CONST_TPRO_DATA_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return null;
	}

	@Override
	protected boolean isLoadLibraries(List<Option> options) {
		return false;
	}

	@Override
	protected boolean shouldSearchAllPaths(Program program, List<Option> options) {
		return false;
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			LoadSpec loadSpec, List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		// Do nothing
	}

	private void addOptionalComponents(Program program, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws Exception {
		boolean addLibobjc =
			OptionUtils.getOption(LIBOBJC_OPTION_NAME, options, LIBOBJC_OPTION_DEFAULT);
		long flags = 0;
		if (OptionUtils.getOption(AUTH_DATA_OPTION_NAME, options, AUTH_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_MAPPING_AUTH_DATA;
		}
		if (OptionUtils.getOption(DIRTY_DATA_OPTION_NAME, options, DIRTY_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_MAPPING_DIRTY_DATA;
		}
		if (OptionUtils.getOption(CONST_DATA_OPTION_NAME, options, CONST_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_MAPPING_CONST_DATA;
		}
		if (OptionUtils.getOption(TEXT_STUBS_OPTION_NAME, options, TEXT_STUBS_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_MAPPING_TEXT_STUBS;
		}
		if (OptionUtils.getOption(CONFIG_DATA_OPTION_NAME, options, CONFIG_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_DYNAMIC_CONFIG_DATA;
		}
		if (OptionUtils.getOption(READ_ONLY_DATA_OPTION_NAME, options,
			READ_ONLY_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_READ_ONLY_DATA;
		}
		if (OptionUtils.getOption(CONST_TPRO_DATA_OPTION_NAME, options,
			CONST_TPRO_DATA_OPTION_DEFAULT)) {
			flags |= DyldCacheMappingAndSlideInfo.DYLD_CACHE_MAPPING_CONST_TPRO_DATA;
		}
		if (!addLibobjc && flags == 0) {
			return;
		}
		try (FileSystemRef fsRef = openDyldCache(program, monitor)) {
			DyldCacheFileSystem fs = (DyldCacheFileSystem) fsRef.getFilesystem();
			Set<GFile> files = new HashSet<>();
			if (addLibobjc) {
				Optional.ofNullable(fs.lookup("/usr/lib/libobjc.A.dylib")).ifPresent(files::add);
			}
			files.addAll(fs.getFiles(flags));
			for (GFile file : files) {
				Group[] children = program.getListing().getDefaultRootModule().getChildren();
				if (Arrays.stream(children).noneMatch(e -> e.getName().contains(file.getPath()))) {
					ByteProvider p = fs.getByteProvider(file, monitor);
					FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, p, monitor);
					MachoExtractProgramBuilder.buildProgram(program, p, fileBytes, log, monitor);
				}
			}
		}
	}

	/**
	 * Attempts to open the given {@link Program}'s originating {@link DyldCacheFileSystem}
	 * 
	 * @param program The {@link Program}
	 * @param monitor A {@link TaskMonitor}
	 * @return A {@link FileSystemRef file system reference} to the open {@link DyldCacheFileSystem}
	 * @throws IOException if an FSRL or IO-related error occurred
	 * @throws CancelledException if the user cancelled the operation
	 */
	public static FileSystemRef openDyldCache(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		FSRL fsrl = FSRL.fromProgram(program);
		if (fsrl == null) {
			throw new IOException("The program does not have an FSRL property");
		}
		String requiredProtocol = DyldCacheFileSystem.DYLD_CACHE_FSTYPE;
		if (!fsrl.getFS().getProtocol().equals(requiredProtocol)) {
			throw new IOException("The program's FSRL protocol is '%s' but '%s' is required"
					.formatted(fsrl.getFS().getProtocol(), requiredProtocol));
		}
		FSRLRoot fsrlRoot = fsrl.getFS();
		return FileSystemService.getInstance().getFilesystem(fsrlRoot, monitor);
	}
}
