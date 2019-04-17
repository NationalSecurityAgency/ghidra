/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.checksums;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.MemoryByteIterator;

import java.io.IOException;
import java.io.InputStream;

class MemoryInputStream extends InputStream {
	MemoryByteIterator it;
	MemoryInputStream(Memory mem, AddressSetView set) {
		it = new MemoryByteIterator(mem, set);
	}
	/**
	 * @see java.io.InputStream#read()
	 */
	@Override
    public int read() throws IOException {
	    try {
			if (it.hasNext()) {
				return it.next() & 0xff;
			}
	    }
	    catch (MemoryAccessException e)  {
	        StackTraceElement ste = e.getStackTrace()[0];
	        throw new IOException(e.toString());
	    }
	    return -1;
	}
}
