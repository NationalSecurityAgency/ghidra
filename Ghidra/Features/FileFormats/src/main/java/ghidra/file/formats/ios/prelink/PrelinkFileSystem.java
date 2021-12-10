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
package ghidra.file.formats.ios.prelink;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import org.apache.commons.collections4.BidiMap;
import org.jdom.JDOMException;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.prelink.PrelinkConstants;
import ghidra.app.util.bin.format.macho.prelink.PrelinkMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.macosx.MacosxLanguageHelper;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = PrelinkFileSystem.IOS_PRELINK_FSTYPE, description = PrelinkConstants.TITLE, priority = FileSystemInfo.PRIORITY_HIGH, factory = GFileSystemBaseFactory.class)
public class PrelinkFileSystem extends GFileSystemBase implements GFileSystemProgramProvider {

	public final static String IOS_PRELINK_FSTYPE = "iosprelink";
	private final static String SYSTEM_KEXT = "System.kext";

	private Map<GFile, PrelinkMap> fileToPrelinkInfoMap = new HashMap<>();
	private Map<Long, GFileImpl> unnamedMachoFileMap = new HashMap<>();
	private Map<GFile, Long> fileToMachoOffsetMap = new HashMap<>();
	private GFileImpl systemKextFile;
	private GFileImpl kernelCacheDirectory;

	public PrelinkFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		super.close();
		fileToPrelinkInfoMap.clear();
		unnamedMachoFileMap.clear();
		fileToMachoOffsetMap.clear();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		try {
			return MachHeader.isMachHeader(provider) &&
				!MachoPrelinkUtils.parsePrelinkXml(provider, monitor).isEmpty();
		}
		catch (JDOMException e) {
			Msg.warn(this, e.getMessage());
			return true; // use KModInfo technique to open
		}
		catch (IOException e) {
			Msg.warn(this, e.getMessage());
			return false;
		}
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening PRELINK file...");

		if (isContainerAlreadyNestedInsideAPrelinkFS()) {
			throw new IOException("Unable to open nested PRELINK file systems.");
		}

		List<Long> machoHeaderOffsets =
			MachoPrelinkUtils.findPrelinkMachoHeaderOffsets(provider, monitor);
		try {
			List<PrelinkMap> prelinkList = MachoPrelinkUtils.parsePrelinkXml(provider, monitor);
			if (!prelinkList.isEmpty()) {
				processPrelinkWithMacho(prelinkList, machoHeaderOffsets, monitor);
			}
		}
		catch (JDOMException e) {
			// Fallback technique to build the filesystem if we could not parse PRELINK.
			// This code path is not tested very well.
			processKModInfoStructures(machoHeaderOffsets, monitor);
		}
		catch (MachException e) {
			throw new IOException(e.getMessage());
		}

		if (systemKextFile != null) {
			systemKextFile.setLength(provider.length());
		}
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		PrelinkMap info = fileToPrelinkInfoMap.get(file);
		return FileAttributes.of(info != null
				? FileAttribute.create(FileAttributeType.COMMENT_ATTR, info.toString())
				: null);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (GFile file : fileToPrelinkInfoMap.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}
			if (kernelCacheDirectory != null) {
				roots.add(kernelCacheDirectory);
			}
			return roots;
		}

		List<GFile> tmp = new ArrayList<>();

		for (GFile file : fileToPrelinkInfoMap.keySet()) {
			if (file.getParentFile() == null) {
				continue;
			}
			if (file.getParentFile().equals(directory)) {
				tmp.add(file);
			}
		}

		if (kernelCacheDirectory != null && kernelCacheDirectory.equals(directory)) {
			List<Long> list = new ArrayList<>(unnamedMachoFileMap.keySet());
			Collections.sort(list);
			for (long offset : list) {
				tmp.add(unnamedMachoFileMap.get(offset));
			}
		}

		return tmp;
	}

	@Override
	public boolean canProvideProgram(GFile file) {
		return fileToMachoOffsetMap.get(file) != null;
	}

	/*
	 * TODO: When we have a PRELINK loader, we should get rid of this method, as well as
	 * GFileSystemProgramProvider and MacosxLanguageHelper.  They should not be needed anymore.
	 */
	@Override
	public Program getProgram(GFile file, LanguageService languageService, TaskMonitor monitor,
			Object consumer) throws Exception {
		Long offset = fileToMachoOffsetMap.get(file);
		if (offset == null) {
			return null;
		}
		MachHeader machHeader =
			MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider, offset, true);
		LanguageCompilerSpecPair lcs = MacosxLanguageHelper.getLanguageCompilerSpecPair(
			languageService, machHeader.getCpuType(), machHeader.getCpuSubType());
		Program program =
			new ProgramDB(file.getName(), lcs.getLanguage(), lcs.getCompilerSpec(), consumer);
		int id = program.startTransaction(getName());
		boolean success = false;
		try {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, offset,
				provider.length() - offset, monitor);
			ByteProvider providerWrapper =
				new ByteProviderWrapper(provider, offset, provider.length() - offset);
			MachoProgramBuilder.buildProgram(program, providerWrapper, fileBytes, new MessageLog(),
				monitor);
			program.setExecutableFormat(MachoLoader.MACH_O_NAME);
			program.setExecutablePath(file.getPath());

			if (file.equals(systemKextFile)) {
				processSystemKext(languageService, program, monitor);
			}

			success = true;
		}
		catch (Exception e) {
			throw e;
		}
		finally {
			program.endTransaction(id, success);
			if (!success) {
				program.release(consumer);
			}
		}
		return program;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		if (isChildOf(systemKextFile, file)) {
			throw new IOException("Unable to open " + file.getName() +
				", it is already contained inside " + systemKextFile.getName());
		}

		Long offset = fileToMachoOffsetMap.get(file);
		if (offset == null) {
			return null;
		}
		return new ByteProviderWrapper(provider, offset, provider.length() - offset,
			file.getFSRL());
	}

	/**
	 * Checks to see if this file system is contained in another PRELINK file system.
	 * 
	 * @return True if this file system is contained in another PRELINK file system; otherwise, false.
	 */
	private boolean isContainerAlreadyNestedInsideAPrelinkFS() {
		FSRL container = getFSRL().getFS().getContainer();
		return container != null && container.getFS().getProtocol().equals(IOS_PRELINK_FSTYPE);
	}

	/**
	 * Processes PRELINK and Macho-O offsets in order to map files to their Mach-O offsets in the 
	 * providers.
	 * 
	 * @param prelinkList The list of discovered {@link PrelinkMap}s.
	 * @param machoHeaderOffsets The list of provider offsets where prelinked Mach-O headers start.
	 * @param monitor A monitor
	 * @throws IOException if an IO-related problem occurred.
	 * @throws MachException if there was a problem parsing Mach-O headers.
	 */
	private void processPrelinkWithMacho(List<PrelinkMap> prelinkList,
			List<Long> machoHeaderOffsets, TaskMonitor monitor) throws IOException, MachException {

		monitor.setMessage("Processing PRELINK with found Mach-O headers...");
		monitor.initialize(prelinkList.size());

		BidiMap<PrelinkMap, Long> map = MachoPrelinkUtils.matchPrelinkToMachoHeaderOffsets(provider,
			prelinkList, machoHeaderOffsets, monitor);

		for (PrelinkMap info : map.keySet()) {

			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			if (info.getPrelinkBundlePath() == null) {
				continue;
			}

			// The following could end up being a directory once we discover it has a child...we'll 
			// handle that in storeFile()
			GFileImpl file =
				GFileImpl.fromPathString(this, root, info.getPrelinkBundlePath(), null, false, 0);

			if (info.getPrelinkExecutableSize() > -1) {
				file.setLength(info.getPrelinkExecutableSize());
			}

			file = storeFile(file, info);

			if (isChildOf(systemKextFile, file)) {
				continue;
			}

			fileToMachoOffsetMap.put(file, map.get(info));
		}
	}

	private void processSystemKext(LanguageService languageService, Program systemProgram,
			TaskMonitor monitor) throws Exception {
		for (GFile file : fileToPrelinkInfoMap.keySet()) {
			if (monitor.isCancelled()) {
				break;
			}

			if (!isChildOf(systemKextFile, file)) {
				continue;
			}

			PrelinkMap prelinkMap = fileToPrelinkInfoMap.get(file);
			if (prelinkMap == null || prelinkMap.getPrelinkExecutableLoadAddr() == -1) {
				continue;
			}

			Address address = systemProgram.getAddressFactory().getDefaultAddressSpace().getAddress(
				prelinkMap.getPrelinkExecutableLoadAddr());

			ByteProvider systemKextProvider =
				new MemoryByteProvider(systemProgram.getMemory(), address);

			MachHeader machHeader = MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE,
				systemKextProvider, 0, false);
			machHeader.parse();

			//MachoLoader loader = new MachoLoader();
			//loader.load( machHeader, systemProgram, new MessageLog(), monitor );

			Namespace namespace = systemProgram.getSymbolTable().createNameSpace(null,
				file.getName(), SourceType.IMPORTED);

			List<SymbolTableCommand> commands =
				machHeader.getLoadCommands(SymbolTableCommand.class);
			for (SymbolTableCommand symbolTableCommand : commands) {
				List<NList> symbols = symbolTableCommand.getSymbols();
				for (NList symbol : symbols) {
					if (monitor.isCancelled()) {
						return;
					}
					Symbol sym = SymbolUtilities.getLabelOrFunctionSymbol(systemProgram,
						symbol.getString(), err -> Msg.error(this, err));
					if (sym != null) {
						sym.setNamespace(namespace);
					}
				}
			}
		}
	}

	private GFileImpl storeFile(GFileImpl file, PrelinkMap info) {
		if (file == null) {
			return file;
		}
		if (file.equals(root)) {
			return file;
		}

		if (systemKextFile == null && file.getName().equals(SYSTEM_KEXT)) {
			systemKextFile = file;
			fileToMachoOffsetMap.put(file, 0L);
		}

		// If 'file' was already added to the map a file and now we see it is really a directory,
		// we need to fix that up.  Similarly, if 'file' was already added to the map as a directory
		// because of the recursive nature of this method (parents will always be treated as
		// directories), we need to maintain its directory status in the map.
		GFileImpl asFile =
			GFileImpl.fromFSRL(this, file.getParentFile(), file.getFSRL(), false, file.getLength());
		GFileImpl asDir =
			GFileImpl.fromFSRL(this, file.getParentFile(), file.getFSRL(), true, file.getLength());
		GFileImpl ret = file;
		if (fileToPrelinkInfoMap.containsKey(asDir) && fileToPrelinkInfoMap.get(asDir) == null) {
			fileToPrelinkInfoMap.put(asDir, info);
			ret = asDir;
		}
		else if (fileToPrelinkInfoMap.containsKey(asFile) &&
			fileToPrelinkInfoMap.get(asFile) != null && file.isDirectory()) {
			PrelinkMap value = fileToPrelinkInfoMap.remove(asFile);
			fileToPrelinkInfoMap.put(asDir, value);
			Long offset = fileToMachoOffsetMap.remove(asFile);
			fileToMachoOffsetMap.put(asDir, offset);
			ret = asDir;
		}
		else if (fileToPrelinkInfoMap.get(file) == null) {
			fileToPrelinkInfoMap.put(file, info);
		}

		GFile parentFile = file.getParentFile();
		storeFile((GFileImpl) parentFile, null);
		return ret;
	}

	private boolean isChildOf(GFile parent, GFile child) {
		if (child == null) {
			return false;
		}
		if (parent == null) {
			return false;
		}
		if (parent.equals(child)) {
			return false;
		}
		return child.getPath().indexOf(parent.getPath()) != -1;
	}

	//--------------------------- Legacy code ----------------------------------------------------

	private void processKModInfoStructures(List<Long> machoHeaderOffsets, TaskMonitor monitor)
			throws IOException {

		Map<PrelinkMap, Long> infoToMachoMap = new HashMap<>();

		kernelCacheDirectory = GFileImpl.fromFilename(this, root, "kernelcache", true, -1, null);

		//
		// if we failed to parse the PRELINK XML file,
		// then look for the kmod_info structure in each KEXT file
		// and use use the
		//
		for (long machoHeaderOffset : machoHeaderOffsets) {
			if (monitor.isCancelled()) {
				break;
			}
			String kextName = "Kext_0x" + Conv.toHexString(machoHeaderOffset) + ".kext";
			try {
				MachHeader header = MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE,
					provider, machoHeaderOffset);
				header.parse();
				String name = findNameOfKext(header, monitor);
				if (name != null) {
					kextName = name + ".kext";
				}
			}
			catch (Exception e) {
				// Failed to parse...shouldn't happen
				Msg.debug(this, "Exception while parsing: " + kextName, e);
			}
			if (machoHeaderOffset == 0x0) {
				kextName = SYSTEM_KEXT; // TODO: this won't happen anymore since the System kext isn't in list of offsets. Problem?
			}
			if (!infoToMachoMap.containsValue(machoHeaderOffset)) {//if there is not already a KEXT at this address, then store it
				long length = provider.length() - machoHeaderOffset;
				GFileImpl file = GFileImpl.fromFilename(this, kernelCacheDirectory, kextName, false,
					length, null);
				unnamedMachoFileMap.put(machoHeaderOffset, file);
				fileToMachoOffsetMap.put(file, machoHeaderOffset);
			}
		}
	}

	private String findNameOfKext(MachHeader header, TaskMonitor monitor) {
		try {
			SegmentCommand dataSegment = header.getSegment(SegmentNames.SEG_DATA);
			if (dataSegment != null) {
				Section dataSection = dataSegment.getSectionByName(SectionNames.DATA);
				if (dataSection != null) {
					if (dataSection.getSize() < 0x1000000) {//don't load too many bytes
						try (InputStream dataStream = dataSection.getDataStream(header)) {
							byte[] bytes = new byte[(int) dataSection.getSize()];
							dataStream.read(bytes);
							String string = new String(bytes);
							int index = string.indexOf("com.apple");
							String kmodNameString = string.substring(index, index + 64).trim();
							StringBuffer buffer = new StringBuffer();
							for (int i = 0; i < kmodNameString.length(); i++) {
								char c = kmodNameString.charAt(i);
								if (LocalFileSystem.isValidNameCharacter(c)) {
									buffer.append(c);
								}
								else {
									buffer.append('_');
								}
							}
							return buffer.toString();
						}
					}
				}
			}
		}
		catch (Exception e) {
			// Fall through and return null to treat the error as not being able to find the name
			Msg.debug(this, "Exception occurred while trying to find the name of kext", e);
		}
		return null;
	}
}
