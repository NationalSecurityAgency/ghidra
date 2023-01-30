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
 * A module. A non-separable unit of code, usually the result of a
 * single compilation, i.e. the symbols associated with a COFF
 * .file symbol.
 */
public class MufomBB3 extends MufomRecord {
	public String module_name = null;

	private void print() {
		String msg = "";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB3(BinaryReader reader) throws IOException {
		Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB3");
		module_name = read_id(reader);
		print();
	}
}
