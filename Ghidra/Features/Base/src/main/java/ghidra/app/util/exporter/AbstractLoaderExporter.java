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
import java.util.List;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.Conv;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * An {@link Exporter} that can export programs imported with a particular {@link Loader}
 */
public abstract class AbstractLoaderExporter extends Exporter {

	/**
	 * Creates a new {@link AbstractLoaderExporter}
	 * 
	 * @param name The display name of this exporter
	 * @param help The {@link HelpLocation} for this exporter
	 */
	protected AbstractLoaderExporter(String name, HelpLocation help) {
		super(name, "", help);
	}
	
	/**
	 * Checks to see if the given file format is supported by this exporter
	 * 
	 * @param fileFormat The file format (loader name) of the program to export
	 * @return True if the given file format is supported by this exporter; otherwise, false
	 */
	protected abstract boolean supportsFileFormat(String fileFormat); 

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getSimpleName());
			return false;
		}
		
		Program program = (Program) domainObj;
		Memory memory = program.getMemory();
		
		String fileFormat = program.getExecutableFormat();
		if (!supportsFileFormat(fileFormat)) {
			log.appendMsg("Unsupported file format: " + fileFormat);
			return false;
		}

		// Write source program's file bytes to a temp file
		File tempFile = File.createTempFile("ghidra_export_", null);
		try (OutputStream out = new FileOutputStream(tempFile, false)) {
			FileBytes[] fileBytes = memory.getAllFileBytes()
					.stream()
					.filter(fb -> program.getExecutablePath().endsWith(fb.getFilename()))
					.toArray(FileBytes[]::new);
			for (FileBytes bytes : fileBytes) {
				FileUtilities.copyStreamToStream(new FileBytesInputStream(bytes), out, monitor);
			}
		}
		
		// Undo relocations in the temp file
		// NOTE: not all relocations are file-backed
		String error = null;
		try (RandomAccessFile fout = new RandomAccessFile(tempFile, "rw")) {
			Iterable<Relocation> relocs = () -> program.getRelocationTable().getRelocations();
			for (Relocation reloc : relocs) {
				AddressSourceInfo info = memory.getAddressSourceInfo(reloc.getAddress());
				if (info == null) {
					continue;
				}
				long offset = info.getFileOffset();
				byte[] bytes = reloc.getBytes();
				if (offset >= 0) {
					if (offset + bytes.length > fout.length()) {
						error = "Relocation at " + reloc.getAddress() + " exceeds file length";
						break;
					}
					fout.seek(offset);
					fout.write(bytes);
				}
			}
		}
		
		// If errors occurred, log them and delete the malformed temp file
		if (error != null) {
			log.appendMsg(error);
			if (!tempFile.delete()) {
				log.appendMsg("Failed to delete malformed file: " + tempFile);
			}
			return false;
		}
		
		// Move temp file to desired output file
		Path from = Paths.get(tempFile.toURI());
		Path to = Paths.get(file.toURI());
		Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return EMPTY_OPTIONS;
	}

	@Override
	public void setOptions(List<Option> options) {
		// No options
	}

	/**
	 * An {@link InputStream} that reads a {@link FileBytes} modified bytes
	 */
	private static class FileBytesInputStream extends InputStream {

		private final FileBytes fileBytes;
		private final long size;
		private long pos;

		/**
		 * Creates a new {@link InputStream} that can read over the modified bytes of the given
		 * {@link FileBytes} object
		 * 
		 * @param fileBytes The {@link FileBytes} to use for the {@link InputStream}
		 */
		FileBytesInputStream(FileBytes fileBytes) {
			this.fileBytes = fileBytes;
			this.size = fileBytes.getSize();
			this.pos = 0;
		}

		@Override
		public int read() throws IOException {
			return pos < size ? Conv.byteToInt(fileBytes.getModifiedByte(pos++)) : -1;
		}

	}
}
