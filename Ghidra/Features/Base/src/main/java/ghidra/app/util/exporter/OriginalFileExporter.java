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
package ghidra.app.util.exporter;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * An {@link Exporter} that can export {@link FileBytes the originally imported file}.
 * <p>
 * WARNING: Programs written to disk with this exporter may be runnable on your native platform.
 * Use caution when exporting potentially malicious programs.
 */
public class OriginalFileExporter extends Exporter {

	private static final String USER_MODS_OPTION_NAME = "Export User Byte Modifications";
	private static final boolean USER_MODS_OPTION_DEFAULT = true;

	private static final String CREATE_DIR_OPTION_NAME = "Save Multiple File Sources To Directory";
	private static final boolean CREATE_DIR_OPTION_DEFAULT = false;

	private List<Option> options;

	/**
	 * Creates a new {@link OriginalFileExporter}
	 */
	public OriginalFileExporter() {
		super("Original File", "", new HelpLocation("ExporterPlugin", "original_file"));
	}

	@Override
	public boolean supportsPartialExport() {
		return false;
	}

	@Override
	public boolean canExportDomainObject(DomainObject domainObject) {
		if (domainObject instanceof Program program) {
			return !program.getMemory().getAllFileBytes().isEmpty();
		}
		return false;
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getSimpleName());
			return false;
		}

		Program program = (Program) domainObj;

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			log.appendMsg("Exporting a program with no file source bytes is not supported");
			return false;
		}

		// Unusual Code Alert!
		// This exporter has an option to save multiple file sources to a newly created directory.
		// If this happens, we treat the file parameter as the new directory to save to.  The newly
		// exported files will each get a filename based on this directory name.  We don't want
		// to use the original FileBytes file name, as it could be dangerous to save the original
		// files to disk with their original filenames.
		File dir = null;
		if (shouldCreateDir()) {
			dir = file;
			if (!FileUtilities.mkdirs(dir)) {
				log.appendMsg("Failed to create directory: " + dir);
				return false;
			}
		}
		else if (allFileBytes.size() > 1) {
			log.appendMsg("WARNING: Program contains more than 1 file source.\n" +
				"Only bytes from the primary (first) file source will be exported.\n" +
				"Enable option to export all file sources to a directory if desired.");
		}

		boolean ret = true;
		for (int i = 0; i < allFileBytes.size(); i++) {
			FileBytes fileBytes = allFileBytes.get(i);
			if (dir != null) {
				file = new File(dir, dir.getName() + "." + i);
			}
			boolean success = shouldExportUserModifications()
					? exportModifiedBytes(file, fileBytes, (Program) domainObj, monitor)
					: exportUnmodifiedlBytes(file, fileBytes, monitor);
			ret &= success;
			if (dir != null) {
				if (success) {
					log.appendMsg("Exported " + fileBytes.getFilename() + " to " + file);
				}
				else {
					log.appendMsg("Failed to export " + fileBytes.getFilename() + " to " + file);
				}
			}
			else {
				break;
			}
		}
		return ret;
	}

	/**
	 * Exports the unmodified {@link FileBytes}
	 * 
	 * @param file The file to export to
	 * @param fileBytes The {@link FileBytes} to export
	 * @param monitor The monitor
	 * @return True if the export succeeded; otherwise, false
	 * @throws IOException If there was IO-related error during the export
	 */
	private boolean exportUnmodifiedlBytes(File file, FileBytes fileBytes, TaskMonitor monitor)
			throws IOException {
		try (OutputStream out = new FileOutputStream(file, false)) {
			FileUtilities.copyStreamToStream(new FileBytesInputStream(fileBytes, false), out,
				monitor);
			return true;
		}
	}

	/**
	 * Exports the modified {@link FileBytes}
	 * 
	 * @param file The file to export to
	 * @param fileBytes The {@link FileBytes} to export
	 * @param program The program to export
	 * @param monitor The monitor
	 * @return True if the export succeeded; otherwise, false
	 * @throws IOException If there was IO-related error during the export
	 */
	private boolean exportModifiedBytes(File file, FileBytes fileBytes, Program program,
			TaskMonitor monitor) throws IOException {

		// Write source program's file bytes to a temp file.
		// This is done to ensure a random access write failure doesn't corrupt a file the user 
		// might be overwriting.
		File tempFile = File.createTempFile("ghidra_export_", null);
		try (OutputStream out = new FileOutputStream(tempFile, false)) {
			FileUtilities.copyStreamToStream(new FileBytesInputStream(fileBytes, true), out,
				monitor);
		}
		
		// Undo relocations in the temp file.
		// NOTE: not all relocations are file-backed, and some are only partially file-backed.
		try (RandomAccessFile fout = new RandomAccessFile(tempFile, "rw")) {
			Iterable<Relocation> relocs = () -> program.getRelocationTable().getRelocations();
			Memory memory = program.getMemory();
			for (Relocation reloc : relocs) {
				Address addr = reloc.getAddress();
				AddressSourceInfo addrSourceInfo = memory.getAddressSourceInfo(addr);
				if (addrSourceInfo == null) {
					continue;
				}
				long offset = addrSourceInfo.getFileOffset();
				if (offset >= 0) {
					MemoryBlockSourceInfo memSourceInfo = addrSourceInfo.getMemoryBlockSourceInfo();
					byte[] bytes = reloc.getBytes();
					int len = Math.min(bytes.length,
						(int) memSourceInfo.getMaxAddress().subtract(addr) + 1);
					fout.seek(offset);
					fout.write(bytes, 0, len);
				}
			}
		}
		catch (Exception e) {
			if (!tempFile.delete()) {
				log.appendMsg("Failed to delete malformed file: " + tempFile);
			}
			return false;
		}
		
		// Success...it is safe to move the temp file to desired output file
		Path from = Paths.get(tempFile.toURI());
		Path to = Paths.get(file.toURI());
		Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		if (options == null) {
			options = new ArrayList<>();
			options.add(new Option(USER_MODS_OPTION_NAME, USER_MODS_OPTION_DEFAULT));
			if (domainObjectService.getDomainObject() instanceof Program program &&
				program.getMemory().getAllFileBytes().size() > 1) {
				options.add(new Option(CREATE_DIR_OPTION_NAME, CREATE_DIR_OPTION_DEFAULT));
			}
		}
		return options;
	}

	@Override
	public void setOptions(List<Option> opt) {
		options = opt;
	}

	/**
	 * Checks to see if user byte modifications should be preserved during the export.
	 * <p>
	 * User byte modifications are any modified byte that does not appear in the relocation table
	 * (relocation table entries are assumed to only be populated by the loader).
	 * 
	 * @return True if user byte modifications should be preserved during the export; otherwise, 
	 *   false
	 */
	private boolean shouldExportUserModifications() {
		return OptionUtils.getOption(USER_MODS_OPTION_NAME, options, USER_MODS_OPTION_DEFAULT);
	}

	/**
	 * Checks to see if a directory should be created when there are multiple {@link FileBytes}
	 * 
	 * @return True if a directory should be created when there are multiple {@link FileBytes}
	 */
	private boolean shouldCreateDir() {
		return OptionUtils.getOption(CREATE_DIR_OPTION_NAME, options, CREATE_DIR_OPTION_DEFAULT);
	}

	/**
	 * An {@link InputStream} that reads a {@link FileBytes} modified or unmodified (original) bytes
	 */
	private static class FileBytesInputStream extends InputStream {

		private final FileBytes fileBytes;
		private final long size;
		private long pos;
		private boolean useModifiedBytes;

		/**
		 * Creates a new {@link InputStream} that can read over the modified bytes of the given
		 * {@link FileBytes} object
		 * 
		 * @param fileBytes The {@link FileBytes} to use for the {@link InputStream}
		 * @param useModifiedBytes True if modified bytes should be read; false for unmodified
		 *   (original) bytes
		 */
		FileBytesInputStream(FileBytes fileBytes, boolean useModifiedBytes) {
			this.fileBytes = fileBytes;
			this.size = fileBytes.getSize();
			this.pos = 0;
			this.useModifiedBytes = useModifiedBytes;
		}

		@Override
		public int read() throws IOException {
			if (pos >= size) {
				return -1;
			}
			byte b;
			if (useModifiedBytes) {
				b = fileBytes.getModifiedByte(pos);
			}
			else {
				b = fileBytes.getOriginalByte(pos);
			}
			pos++;
			return Byte.toUnsignedInt(b);
		}

	}
}
