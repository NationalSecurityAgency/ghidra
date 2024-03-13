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
public class MachoFileSetFileSystem extends AbstractFileSystem<FileSetEntryCommand> {

	public static final String MACHO_FILESET_FSTYPE = "machofileset";

	private ByteProvider provider;
	private ByteProvider fixedUpProvider;
	private Map<FileSetEntryCommand, List<SegmentCommand>> entrySegmentMap;

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
			MachHeader header = new MachHeader(provider).parse();
			SegmentCommand textSegment = header.getSegment(SegmentNames.SEG_TEXT);
			if (textSegment == null) {
				throw new MachException(SegmentNames.SEG_TEXT + " not found!");
			}
			for (FileSetEntryCommand cmd : header.getLoadCommands(FileSetEntryCommand.class)) {
				fsIndex.storeFile(cmd.getFileSetEntryId().getString(), fsIndex.getFileCount(),
					false, -1, cmd);
				MachHeader entryHeader = new MachHeader(provider, cmd.getFileOffset());
				entrySegmentMap.put(cmd, entryHeader.parseSegments());
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
		FileSetEntryCommand cmd = fsIndex.getMetadata(file);
		if (cmd == null) {
			return null;
		}
		try {
			return MachoFileSetExtractor.extractFileSetEntry(fixedUpProvider, cmd.getFileOffset(),
				file.getFSRL(), monitor);
		}
		catch (MachException e) {
			throw new IOException(
				"Invalid Mach-O header detected at 0x%x".formatted(cmd.getFileOffset()));
		}
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		FileSetEntryCommand cmd = fsIndex.getMetadata(file);
		if (cmd != null) {
			result.add(NAME_ATTR, cmd.getFileSetEntryId().getString());
			result.add(PATH_ATTR, cmd.getFileSetEntryId().getString());
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
	public Map<FileSetEntryCommand, List<SegmentCommand>> getEntrySegmentMap() {
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
		fsIndex.clear();
		entrySegmentMap.clear();
	}
}
