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
 * A global subprogram.
 */
public class MufomBB4 extends MufomRecord {
	public String function_name = null;
	public long type_index = -1;
	public long code_block_address = -1;

	private void print() {
		String msg = "";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB4(BinaryReader reader) throws IOException {
		Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB4");
		function_name = read_id(reader);
		if (0 != read_int(reader)) {
			Msg.info(this, "Bad stack space");
			throw new IOException();
		}
		type_index = read_int(reader);
		code_block_address = read_int(reader);
		print();
	}
}
