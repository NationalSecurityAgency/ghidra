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
import java.util.*;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.prelink.PrelinkMap;
import ghidra.app.util.bin.format.ubi.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFolder;
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
			MachHeader machHeader =
				MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider);
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
			List<PrelinkMap> prelinkList = MachoPrelinkUtils.parsePrelinkXml(provider, monitor);
			if (!prelinkList.isEmpty()) {
				MachoPrelinkProgramBuilder.buildProgram(program, provider, fileBytes, prelinkList,
					log, monitor);
			}
			else {
				MachoProgramBuilder.buildProgram(program, provider, fileBytes, log, monitor);
			}
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
	protected boolean importLibrary(String libName, DomainFolder libFolder, File libFile,
			LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer,
			Set<String> unprocessedLibs, List<Program> programList, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (!libFile.isFile()) {
			return false;
		}

		try (ByteProvider provider = new RandomAccessByteProvider(libFile)) {

			FatHeader header =
				FatHeader.createFatHeader(RethrowContinuesFactory.INSTANCE, provider);
			List<FatArch> architectures = header.getArchitectures();

			if (architectures.isEmpty()) {
				log.appendMsg("WARNING! No archives found in the UBI: " + libFile);
				return false;
			}

			for (FatArch architecture : architectures) {

				// Note: The creation of the byte provider that we pass to the importer deserves a
				// bit of explanation:
				//
				// At this point in the process we have a FatArch, which provides access to the 
				// underlying bytes for the Macho in the form of an input stream. From that we could
				// create a byte provider. That doesn't work however. Here's why:
				//
				// The underlying input stream in the FatArch has already been parsed and the first
				// 4 (magic) bytes read. If we create a provider from that stream and pass it to 
				// the parent import method, we'll have a problem because that parent method will 
				// try to read those first 4 magic bytes again, which violates the contract of the 
				// input stream provider (you can't read the same bytes over again) and will throw 
				// an exception. To avoid that, just create the provider from the original file 
				// provider, and not from the FatArch input stream. 
				try (ByteProvider bp = new ByteProviderWrapper(provider, architecture.getOffset(),
					architecture.getSize())) {
					if (super.importLibrary(libName, libFolder, libFile, bp, loadSpec, options, log,
						consumer, unprocessedLibs, programList, monitor)) {
						return true;
					}
				}
			}
		}
		catch (UbiException | MachException ex) {
			// Not a Universal Binary file; just continue and process as a normal file. This is 
			// not an error condition so no need to log.
		}

		return super.importLibrary(libName, libFolder, libFile, loadSpec, options, log, consumer,
			unprocessedLibs, programList, monitor);
	}
}
