/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License; Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing; software
 * distributed under the License is distributed on an "AS IS" BASIS;
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND; either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.mufom;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

/*
 * The module portion of a section.
 */
public class MufomBB11 extends MufomRecord {
	public long section_type = -1;
	public long section_number = -1;
	public long section_offset = -1;

	private void print() {
		String msg = "";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB11(BinaryReader reader) throws IOException {
		Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB11");
		String zero = read_id(reader);
		if (zero.length() != 0) {
			Msg.info(this, "bad zero");
			throw new IOException();
		}
		section_type = read_int(reader);
		section_number = read_int(reader);
		section_offset = read_int(reader);
		print();
	}
}
