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
import java.util.List;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

abstract class AbstractExecutableExporter extends Exporter {

	protected AbstractExecutableExporter(String name, String extension, HelpLocation help) {
		super(name, extension, help);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;
		Memory memory = program.getMemory();

		try (OutputStream out = new FileOutputStream(file, false)) {
			FileBytes[] fileBytes = memory.getAllFileBytes()
				.stream()
				.filter((fb) -> fb.getFilename().equals(program.getName()))
				.toArray(FileBytes[]::new);
			for (FileBytes bytes : fileBytes) {
				FileBytesInputStream byteStream = new FileBytesInputStream(bytes);
				FileUtilities.copyStreamToStream(byteStream, out, monitor);
			}
		}
		try (RandomAccessFile fout = new RandomAccessFile(file, "rw")) {
				Iterable<Relocation> relocs =
					() -> program.getRelocationTable().getRelocations();
				for (Relocation reloc : relocs) {
					AddressSourceInfo info = memory.getAddressSourceInfo(reloc.getAddress());
					// some relocations report negative offsets
					if (info.getFileOffset() >= 0) {
						// seek incase we are larger than an int
						fout.seek(info.getFileOffset());
						fout.write(reloc.getBytes());
					}
				}
			}

		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return EMPTY_OPTIONS;
	}

	@Override
	public void setOptions(List<Option> options) {
	}

	private static class FileBytesInputStream extends InputStream {

		private long pos = 0;
		private final FileBytes bytes;

		FileBytesInputStream(FileBytes bytes) {
			this.bytes = bytes;
		}

		@Override
		public int read() throws IOException {
			if (pos < bytes.getSize()) {
				return bytes.getModifiedByte(pos++) & 0xff;
			}
			return -1;
		}

	}
}
