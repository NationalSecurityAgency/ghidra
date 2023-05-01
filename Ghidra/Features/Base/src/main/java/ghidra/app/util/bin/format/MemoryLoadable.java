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
package ghidra.app.util.bin.format;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;
import java.util.function.BiConsumer;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

/**
 * <code>MemoryLoadable</code> serves as both a marker interface which identifies a memory 
 * loadable portion of a binary file (supports use as a {@link Hashtable} key).  In addition,
 * it serves to supply the neccessary input stream to create a {@link MemoryBlock}.
 * 
 */
public interface MemoryLoadable {

	/**
	 * Determine if the use of input stream decompression or filtering via an extension is neccessary. 
	 * If this method returns true and a 
	 * {@link #getFilteredLoadInputStream(ElfLoadHelper, Address, long, BiConsumer) filtered stream} 
	 * is required and will prevent the use of a direct mapping to file bytes for affected memory 
	 * regions.
	 * @param elfLoadHelper ELF load helper
	 * @param start memory load address
	 * @return true if the use of a filtered input stream is required
	 */
	public boolean hasFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, Address start);

	/**
	 * Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
	 * See {@link #hasFilteredLoadInputStream(ElfLoadHelper, Address)}.
	 * @param elfLoadHelper ELF load helper
	 * @param start memory load address
	 * @param dataLength the in-memory data length in bytes (actual bytes read from dataInput may be more)
	 * @param errorConsumer consumer that will accept errors which may occur during stream
	 * decompression, if null Msg.error() will be used.
	 * @return filtered input stream or original input stream
	 * @throws IOException if error initializing filtered input stream
	 */
	public InputStream getFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, Address start,
			long dataLength, BiConsumer<String, Throwable> errorConsumer) throws IOException;

	/**
	 * {@return raw data input stream associated with this loadable object.}
	 * @throws IOException if error initializing input stream
	 */
	public InputStream getRawInputStream() throws IOException;

}
