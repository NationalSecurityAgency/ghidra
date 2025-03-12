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

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.golang.GoConstants;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.DyldArchitecture;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.app.util.bin.format.ubi.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.model.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * A {@link Loader} for Mach-O files.
 */
public class MachoLoader extends AbstractLibrarySupportLoader {

	public final static String MACH_O_NAME = "Mac OS X Mach-O";
	private static final long MIN_BYTE_LENGTH = 4;

	public static final String REEXPORT_OPTION_NAME = "Perform Reexports";
	static final boolean REEXPORT_OPTION_DEFAULT = true;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Efficient check to fail fast
		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		// Efficient check to fail fast
		byte[] magicBytes = provider.readBytes(0, 4);
		if (!MachConstants.isMagic(LittleEndianDataConverter.INSTANCE.getInt(magicBytes))) {
			return loadSpecs;
		}

		try {
			MachHeader machHeader = new MachHeader(provider);
			String magic =
				CpuTypes.getMagicString(machHeader.getCpuType(), machHeader.getCpuSubType());
			String compiler = detectCompilerName(machHeader);
			List<QueryResult> results = QueryOpinionService.query(MACH_O_NAME, magic, compiler);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, machHeader.getImageBase(), result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, machHeader.getImageBase(), true));
			}
		}
		catch (MachException e) {
			// not a problem, just don't add it
		}
		return loadSpecs;
	}

	private String detectCompilerName(MachHeader machHeader) throws IOException {
		List<String> sectionNames = machHeader.parseSegments()
				.stream()
				.flatMap(seg -> seg.getSections().stream())
				.map(section -> section.getSectionName())
				.toList();
		if (SwiftUtils.isSwift(sectionNames)) {
			return SwiftUtils.SWIFT_COMPILER;
		}
		if (GoRttiMapper.hasGolangSections(sectionNames)) {
			return GoConstants.GOLANG_CSPEC_NAME;
		}
		return null;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

			// A Mach-O file may contain PRELINK information.  If so, we use a special
			// program builder that knows how to deal with it.
			if (MachoPrelinkUtils.isMachoPrelink(provider, monitor) ||
				MachoPrelinkUtils.isMachoFileset(provider)) {
				MachoPrelinkProgramBuilder.buildProgram(program, provider, fileBytes, log, monitor);
			}
			else {
				MachoProgramBuilder.buildProgram(program, provider, fileBytes, log, monitor);
			}
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
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		if (!loadIntoProgram) {
			list.add(new Option(REEXPORT_OPTION_NAME, REEXPORT_OPTION_DEFAULT,
				Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-reexport"));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(REEXPORT_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public String getName() {
		return MACH_O_NAME;
	}

	@Override
	protected boolean isValidSearchPath(FSRL fsrl, LoadSpec loadSpec, TaskMonitor monitor)
			throws CancelledException {
		FileSystemService fsService = FileSystemService.getInstance();
		try (ByteProvider provider = fsService.getByteProvider(fsrl, loggingDisabled, monitor)) {
			if (!DyldCacheUtils.isDyldCache(provider)) {
				return true;
			}
			DyldCacheHeader header = new DyldCacheHeader(new BinaryReader(provider, true));
			DyldArchitecture dyld = header.getArchitecture();
			LanguageCompilerSpecPair lcs = loadSpec.getLanguageCompilerSpec();
			String processor = lcs.getLanguage().getProcessor().toString().toLowerCase();
			boolean is64bit = lcs.getLanguage()
					.getAddressFactory()
					.getDefaultAddressSpace()
					.getPointerSize() == 8;
			return switch (processor) {
				case "x86" -> dyld.isX86() && is64bit == dyld.is64bit();
				case "aarch64" -> dyld.isARM() && dyld.is64bit();
				case "arm" -> dyld.isARM() && !dyld.is64bit();
				case "powerpc" -> dyld.isPowerPC();
				default -> false;
			};
		}
		catch (IOException e) {
			// Problem occurred...assume it's valid
			return true;
		}
	}

	/**
	 * Overrides the default implementation to account for Universal Binary (UBI) files. 
	 * These must be specially parsed to find the internal file matching the current architecture.
	 * <p>
	 * {@link FatHeader} is used to parse the file to determine if it is a
	 * UBI. If so, each file within the archive is run through the import process until one is
	 * found that is successful (meaning it matches the correct architecture). Only one file
	 * in the UBI will ever be imported. If the provided file is NOT a UBI, default 
	 * import method will be invoked. 
	 * <hr>
	 * {@inheritDoc}
	 */
	@Override
	protected ByteProvider createLibraryByteProvider(FSRL libFsrl, LoadSpec loadSpec,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {


		ByteProvider provider = super.createLibraryByteProvider(libFsrl, loadSpec, log, monitor);

		try {
			FatHeader header = new FatHeader(provider);
			List<FatArch> architectures = header.getArchitectures();

			if (architectures.isEmpty()) {
				log.appendMsg("WARNING! No archives found in the UBI: " + libFsrl);
				return null;
			}

			for (FatArch architecture : architectures) {
				ByteProvider bp = new ByteProviderWrapper(provider, architecture.getOffset(),
					architecture.getSize()) {

					@Override // Ensure the parent provider gets closed when the wrapper does
					public void close() throws IOException {
						super.provider.close();
					}
				};
				LoadSpec libLoadSpec = matchSupportedLoadSpec(loadSpec, bp);
				if (libLoadSpec != null) {
					return bp;
				}
			}
		}
		catch (UbiException | MachException ex) {
			// Not a Universal Binary file; just continue and process as a normal file. This is 
			// not an error condition so no need to log.
		}

		return provider;
	}

	/**
	 * Special Mach-O library file resolver to account for a "Versions" subdirectory being inserted
	 * in the library lookup path.  For example, a reference to:
	 * <p>
	 * {@code /System/Library/Frameworks/Foundation.framework/Foundation}
	 * <p>
	 * might be found at:
	 * <p>
	 * {@code /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation}
	 * <hr>
	 * {@inheritDoc}
	 */
	@Override
	protected FSRL resolveLibraryFile(GFileSystem fs, String library) throws IOException {
		FSRL fsrl = super.resolveLibraryFile(fs, library);
		if (fsrl != null) {
			return fsrl;
		}
		String libraryParentPath = FilenameUtils.getFullPath(library);
		String libraryName = FilenameUtils.getName(library);
		GFile libraryParentDir = fs.lookup(libraryParentPath);
		if (libraryParentDir != null) {
			for (GFile file : fs.getListing(libraryParentDir)) {
				if (file.isDirectory() && file.getName().equals("Versions")) {
					String versionsPath = joinPaths(libraryParentPath, file.getName());
					List<GFile> versionListion = fs.getListing(file);
					if (!versionListion.isEmpty()) {
						GFile specificVersionDir = versionListion.get(0);
						if (specificVersionDir.isDirectory()) {
							return resolveLibraryFile(fs,
								joinPaths(versionsPath, specificVersionDir.getName(), libraryName));
						}
					}
				}
				else if (file.isDirectory()) {
					continue;
				}
				if (file.getName().equals(libraryName)) {
					return file.getFSRL();
				}
			}
		}
		return null;
	}

	/**
	 * Checks to see if reexports should be performed
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if reexports should be performed; otherwise, false
	 */
	private boolean shouldPerformReexports(List<Option> options) {
		return OptionUtils.getOption(REEXPORT_OPTION_NAME, options, REEXPORT_OPTION_DEFAULT);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * If we aren't loading libraries, we still want to search all paths if the reexport option is 
	 * set and the Mach-O actually has {@code LC_REEXPORT_DYLIB} entries. 
	 */
	@Override
	protected boolean shouldSearchAllPaths(Program program, List<Option> options) {
		if (super.shouldSearchAllPaths(program, options)) {
			return true;
		}
		if (shouldPerformReexports(options)) {
			try {
				ByteProvider provider = new MemoryByteProvider(program.getMemory(),
					program.getImageBase());
				if (new MachHeader(provider).parseAndCheck(LoadCommandTypes.LC_REEXPORT_DYLIB)) {
					return true;
				}
			}
			catch (IOException | MachException e) {
				Msg.error(this, "Failed to parse Mach-O header for: " + program.getName());
			}
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The goal here is to add each reexported library to the {@code unprocessed} list at the 
	 * current {@code depth} to be sure they get loaded. However, if the current depth is 1, we 
	 * need to marked them as "discard" so we know not to save them in the end (since their actual
	 * depth would have prevented their save as a normal library)
	 */
	@Override
	protected void processLibrary(Program lib, String libName, FSRL libFsrl, ByteProvider provider,
			Queue<UnprocessedLibrary> unprocessed, int depth, LoadSpec loadSpec,
			List<Option> options, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (!shouldPerformReexports(options)) {
			return;
		}

		try {
			for (String path : getReexportPaths(lib)) {
				unprocessed.add(new UnprocessedLibrary(path, depth, depth == 1));
			}
		}
		catch (MachException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Gets a {@link List} of reexport library paths from the given {@link Program}
	 *  
	 * @param program The {@link Program}
	 * @return A {@link List} of reexport library paths from the given {@link Program}
	 * @throws MachException if there was a problem parsing the Mach-O {@link Program}
	 * @throws IOException if there was an IO-related error
	 */
	private List<String> getReexportPaths(Program program) throws MachException, IOException {
		ByteProvider p = new MemoryByteProvider(program.getMemory(), program.getImageBase());
		return new MachHeader(p).parseReexports()
				.stream()
				.map(DynamicLibraryCommand::getDynamicLibrary)
				.map(DynamicLibrary::getName)
				.map(LoadCommandString::getString)
				.toList();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Adds reexported symbols to each {@link Loaded} {@link Program}.
	 */
	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			LoadSpec loadSpec, List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (shouldPerformReexports(options)) {
			
			List<DomainFolder> searchFolders =
				getLibrarySearchFolders(loadedPrograms, project, options);

			List<LibrarySearchPath> searchPaths =
				getLibrarySearchPaths(loadedPrograms.getFirst().getDomainObject(), loadSpec,
					options, messageLog, monitor);

			monitor.initialize(loadedPrograms.size());
			for (Loaded<Program> loadedProgram : loadedPrograms) {
				monitor.increment();

				Program program = loadedProgram.getDomainObject();
				int id = program.startTransaction("Reexporting");
				try {
					reexport(program, loadedPrograms, searchFolders, searchPaths, options, monitor,
						messageLog);
				}
				catch (Exception e) {
					messageLog.appendException(e);
				}
				finally {
					program.endTransaction(id, true);
				}
			}
		}

		super.postLoadProgramFixups(loadedPrograms, project, loadSpec, options, messageLog,
			monitor);
	}

	/**
	 * "Reexports" symbols from to a {@link Program}
	 * 
	 * @param program The {@link Program} to receive the reexports
	 * @param loadedPrograms A {@link List} of {@link Loaded} {@link Program}s to find get the
	 *   reexportable symbols from
	 * @param searchFolders A {@link List} of project folders that may contain already-loaded
	 *   {@link Program}s with reexportable symbols
	 * @param searchPaths A {@link List} of file system search paths that will be searched
	 * @param options The load options
	 * @param monitor A cancelable task monitor
	 * @param messageLog The log
	 * @throws CancelledException if the user cancelled the load operation
	 * @throws IOException if there was an IO-related error during the load
	 */
	private void reexport(Program program, List<Loaded<Program>> loadedPrograms,
			List<DomainFolder> searchFolders, List<LibrarySearchPath> searchPaths,
			List<Option> options, TaskMonitor monitor, MessageLog messageLog)
			throws CancelledException, Exception {

		for (String path : getReexportPaths(program)) {
			monitor.checkCancelled();
			Program programToRelease = null;
			try {
				Loaded<Program> match = findLibraryInLoadedList(loadedPrograms, path);
				Program lib = null;
				if (match != null) {
					lib = match.getDomainObject();
				}
				if (lib == null) {
					for (DomainFolder searchFolder : searchFolders) {
						DomainFile df =
							findLibraryInProject(path, searchFolder, searchPaths, options, monitor);
						if (df != null) {
							DomainObject obj = df.getDomainObject(this, true, true, monitor);
							if (obj instanceof Program p) {
								lib = p;
								programToRelease = p;
							}
							break;
						}
					}
				}
				if (lib == null) {
					continue;
				}
				List<Symbol> reexportedSymbols = CollectionUtils
						.asStream(lib.getSymbolTable().getExternalEntryPointIterator())
						.map(lib.getSymbolTable()::getPrimarySymbol)
						.filter(Objects::nonNull)
						.toList();
				Address addr = MachoProgramUtils.addExternalBlock(program,
					reexportedSymbols.size() * 8, messageLog);
				monitor.initialize(reexportedSymbols.size(), "Reexporting symbols...");
				for (Symbol symbol : reexportedSymbols) {
					monitor.increment();
					String name = SymbolUtilities.replaceInvalidChars(symbol.getName(), true);
					program.getSymbolTable().addExternalEntryPoint(addr);
					program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
					Function function = program.getFunctionManager()
							.createFunction(name, addr, new AddressSet(addr), SourceType.IMPORTED);
					ExternalLocation loc = program.getExternalManager()
							.addExtLocation(path, name, null, SourceType.IMPORTED);
					function.setThunkedFunction(loc.createFunction());

					addr = addr.add(8);
				}
			}
			finally {
				if (programToRelease != null) {
					programToRelease.release(this);
				}
			}
		}
	}
}
