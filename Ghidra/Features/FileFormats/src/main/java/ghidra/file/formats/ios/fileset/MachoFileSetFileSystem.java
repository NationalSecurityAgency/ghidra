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
package ghidra.file.formats.ios.fileset;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.DyldFixup;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.ios.ExtractedMacho;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystem} implementation for Mach-O file set entries
 */
@FileSystemInfo(type = MachoFileSetFileSystem.MACHO_FILESET_FSTYPE, description = "Mach-O file set", factory = MachoFileSetFileSystemFactory.class)
public class MachoFileSetFileSystem extends AbstractFileSystem<MachoFileSetEntry> {

	public static final String MACHO_FILESET_FSTYPE = "machofileset";

	private ByteProvider provider;
	private ByteProvider fixedUpProvider;
	private MachHeader header;
	private Map<MachoFileSetEntry, List<SegmentCommand>> entrySegmentMap;

	/**
	 * Creates a new {@link MachoFileSetFileSystem}
	 * 
	 * @param fsFSRL {@link FSRLRoot} of this file system
	 * @param provider The {@link ByteProvider} that contains the file system
	 */
	public MachoFileSetFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		super(fsFSRL, FileSystemService.getInstance());
		this.provider = provider;
		this.entrySegmentMap = new HashMap<>();
	}

	/**
	 * Mounts this file system
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException If there was an issue mounting the file system
	 * @throws CancelledException If the user cancelled the operation
	 */
	public void mount(TaskMonitor monitor) throws IOException, CancelledException {
		MessageLog log = new MessageLog();
		try {
			monitor.setMessage("Opening Mach-O file set...");
			header = new MachHeader(provider).parse();
			SegmentCommand textSegment = header.getSegment(SegmentNames.SEG_TEXT);
			if (textSegment == null) {
				throw new MachException(SegmentNames.SEG_TEXT + " not found!");
			}

			// File set entries
			for (FileSetEntryCommand cmd : header.getLoadCommands(FileSetEntryCommand.class)) {
				MachoFileSetEntry entry = new MachoFileSetEntry(cmd.getFileSetEntryId().getString(),
					cmd.getFileOffset(), false);
				fsIndex.storeFile(entry.id(), fsIndex.getFileCount(), false, -1, entry);
				entrySegmentMap.put(entry,
					new MachHeader(provider, entry.offset()).parseSegments());
			}

			// BRANCH segments, if present
			SegmentCommand branchStubs = header.getSegment(SegmentNames.SEG_BRANCH_STUBS);
			if (branchStubs != null) {
				MachoFileSetEntry entry =
					new MachoFileSetEntry(SegmentNames.SEG_BRANCH_STUBS.substring(2), 0, true);
				fsIndex.storeFile(entry.id(), fsIndex.getFileCount(), false, -1, entry);
				entrySegmentMap.put(entry, List.of(branchStubs));
			}
			SegmentCommand branchGots = header.getSegment(SegmentNames.SEG_BRANCH_GOTS);
			if (branchGots != null) {
				MachoFileSetEntry entry =
					new MachoFileSetEntry(SegmentNames.SEG_BRANCH_GOTS.substring(2), 0, true);
				fsIndex.storeFile(entry.id(), fsIndex.getFileCount(), false, -1, entry);
				entrySegmentMap.put(entry, List.of(branchGots));
			}

			monitor.setMessage("Getting chained pointers...");
			BinaryReader reader = new BinaryReader(provider, header.isLittleEndian());
			List<DyldFixup> fixups = new ArrayList<>();
			long imagebase = textSegment.getVMaddress();
			for (DyldChainedFixupsCommand loadCommand : header
					.getLoadCommands(DyldChainedFixupsCommand.class)) {
				fixups.addAll(loadCommand.getChainedFixups(reader, imagebase, null, log,
					monitor));
			}

			monitor.initialize(fixups.size(), "Fixing chained pointers...");
			byte[] bytes = provider.readBytes(0, provider.length());
			for (DyldFixup fixup : fixups) {
				byte[] newBytes = ExtractedMacho.toBytes(fixup.value(), fixup.size());
				System.arraycopy(newBytes, 0, bytes, (int) fixup.offset(), newBytes.length);
			}
			fixedUpProvider = new ByteArrayProvider(bytes);
		}
		catch (MachException e) {
			throw new IOException(e);
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		MachoFileSetEntry entry = fsIndex.getMetadata(file);
		if (entry == null) {
			return null;
		}
		try {
			if (entry.isBranchSegment()) {
				return MachoFileSetExtractor.extractSegment(fixedUpProvider,
					header.getSegment("__" + entry.id()), file.getFSRL(), monitor);
			}
			return MachoFileSetExtractor.extractFileSetEntry(fixedUpProvider, entry.offset(),
				file.getFSRL(), monitor);
		}
		catch (MachException e) {
			throw new IOException(
				"Invalid Mach-O header detected at 0x%x".formatted(entry.offset()));
		}
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		MachoFileSetEntry entry = fsIndex.getMetadata(file);
		if (entry != null) {
			result.add(NAME_ATTR, entry.id());
			result.add(PATH_ATTR, entry.id());
		}
		return result;
	}

	/**
	 * Gets the open Mach-O file set {@link ByteProvider}.  This is the original
	 * {@link ByteProvider} that this file system opened.
	 * 
	 * @return The opened Mach-O file set {@link ByteProvider}, or null if it has is not open
	 */
	public ByteProvider getMachoFileSetProvider() {
		return provider;
	}

	/**
	 * {@return the map of file set entry segments}
	 */
	public Map<MachoFileSetEntry, List<SegmentCommand>> getEntrySegmentMap() {
		return entrySegmentMap;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		if (fixedUpProvider != null) {
			fixedUpProvider.close();
			fixedUpProvider = null;
		}
		if (header != null) {
			header = null;
		}
		fsIndex.clear();
		entrySegmentMap.clear();
	}
}
