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

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.*;

import ghidra.app.util.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.ubi.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for Mach-O files.
 */
public class MachoLoader extends AbstractLibrarySupportLoader {

	public final static String MACH_O_NAME = "Mac OS X Mach-O";
	private static final long MIN_BYTE_LENGTH = 4;

	/** Loader option to add relocation entries for chained fixups */
	static final String ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME =
		"Add relocation entries for chained fixups";

	/** Default value for loader option add chained fixups relocation entries */
	static final boolean ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT = true;

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
			List<QueryResult> results = QueryOpinionService.query(getName(), magic, null);
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

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

			// A Mach-O file may contain PRELINK information.  If so, we use a special
			// program builder that knows how to deal with it.
			if (MachoPrelinkUtils.isMachoPrelink(provider, monitor)) {
				MachoPrelinkProgramBuilder.buildProgram(program, provider, fileBytes,
					shouldAddChainedFixupsRelocations(options), log, monitor);
			}
			else {
				MachoProgramBuilder.buildProgram(program, provider, fileBytes,
					shouldAddChainedFixupsRelocations(options), log, monitor);
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
	public String getName() {
		return MACH_O_NAME;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		if (!loadIntoProgram) {
			list.add(new Option(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME,
				ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-addChainedFixupsRelocations"));
		}
		return list;
	}

	private boolean shouldAddChainedFixupsRelocations(List<Option> options) {
		return OptionUtils.getOption(ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_NAME, options,
			ADD_CHAINED_FIXUPS_RELOCATIONS_OPTION_DEFAULT);
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
	 */
	@Override
	protected ByteProvider createLibraryByteProvider(File libFile, LoadSpec loadSpec, MessageLog log)
			throws IOException {

		if (!libFile.isFile()) {
			return null;
		}

		ByteProvider provider = new FileByteProvider(libFile,
			FileSystemService.getInstance().getLocalFSRL(libFile), AccessMode.READ);

		try {
			FatHeader header = new FatHeader(provider);
			List<FatArch> architectures = header.getArchitectures();

			if (architectures.isEmpty()) {
				log.appendMsg("WARNING! No archives found in the UBI: " + libFile);
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
}
