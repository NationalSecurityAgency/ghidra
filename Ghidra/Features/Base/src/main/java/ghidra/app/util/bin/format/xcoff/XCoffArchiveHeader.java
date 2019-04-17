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
package ghidra.app.util.bin.format.xcoff;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

import java.io.IOException;

public class XCoffArchiveHeader {
	private static final int _20 = 20;

	private byte [] fl_magic;   // Archive magic string
	private byte [] fl_memoff;  // Offset to member table
	private byte [] fl_gstoff;  // Offset to global symbol table
	private byte [] fl_gst64off;// Offset to global symbol table for 64-bit objects  
	private byte [] fl_fstmoff; // Offset to first archive member
	private byte [] fl_lstmoff; // Offset to last archive member
	private byte [] fl_freeoff; // Offset to first member on free list

	public XCoffArchiveHeader(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);

		fl_magic    = reader.readNextByteArray(XCoffArchiveConstants.MAGIC_LENGTH);
		fl_memoff   = reader.readNextByteArray(_20);
		fl_gstoff   = reader.readNextByteArray(_20);
		fl_gst64off = reader.readNextByteArray(_20);
		fl_fstmoff  = reader.readNextByteArray(_20);
		fl_lstmoff  = reader.readNextByteArray(_20);
		fl_freeoff  = reader.readNextByteArray(_20);
	}

	public String fl_magic() {
		return (new String(fl_magic)).trim();
	}

	public long fl_memoff() {
		return Long.parseLong((new String(fl_memoff)).trim());
	}

	public long fl_gstoff() {
		return Long.parseLong((new String(fl_gstoff)).trim());
	}

	public long fl_gst64off() {
		return Long.parseLong((new String(fl_gst64off)).trim());
	}

	public long fstmoff() {
		return Long.parseLong((new String(fl_fstmoff)).trim());
	}

	public long lstmoff() {
		return Long.parseLong((new String(fl_lstmoff)).trim());
	}

	public long fl_freeoff() {
		return Long.parseLong((new String(fl_freeoff)).trim());
	}

}
