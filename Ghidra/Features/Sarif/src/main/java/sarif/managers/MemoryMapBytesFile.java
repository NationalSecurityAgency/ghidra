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
package sarif.managers;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class MemoryMapBytesFile {

	private OutputStream os;
	private String fileName;
	private int bytesWritten;
	private Memory memory;

	public MemoryMapBytesFile(Program program, String fileName) throws IOException {
		memory = program.getMemory();
		fileName += ".bytes";
		File file = new File(fileName);
		this.fileName = file.getName();
		if (file.exists()) {
			file.delete();
		}
		os = new BufferedOutputStream(new FileOutputStream(file));
	}

	void close() throws IOException {
		os.close();
	}

	public String getFileName() {
		return fileName;
	}

	public int getOffset() {
		return bytesWritten;
	}

	public void writeBytes(AddressRange range) throws IOException {
		try {
			int BUFSIZE = 32 * 1024;
			long size = range.getLength();
			byte[] buf = new byte[(int) Math.min(size, BUFSIZE)];
			Address addr = range.getMinAddress();
			int n = 0;
			while (size > 0) {
				addr = addr.addNoWrap(n);
				n = memory.getBytes(addr, buf);
				os.write(buf, 0, n);
				bytesWritten += n;
				size -= n;
			}
		} catch (AddressOverflowException e) {
			throw new IOException(e.getMessage());
		} catch (MemoryAccessException e) {
			throw new IOException(e.getMessage());
		} catch (IOException e) {
			throw new IOException(e.getMessage());
		}
	}
}
