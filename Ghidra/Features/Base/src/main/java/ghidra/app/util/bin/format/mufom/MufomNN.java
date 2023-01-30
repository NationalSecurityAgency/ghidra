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
 * 11.3 NN (name) Command
 *
 * NN-command → “N” N-variable “,” name “.”
 * N-variable → “N” hexnumber
 * name → char-string
 *
 * {$F0}{n1}{Id}
 */
public class MufomNN extends MufomRecord {
	public static final String NAME = "NN";
	public static final int record_type = MufomType.MUFOM_CMD_NN;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long symbol_name_index = -1;
	public String symbol_name = null;
	public boolean missing = false;

	private void print() {
		String msg = NAME + ": '" + symbol_name + "' " + symbol_name_index;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomNN(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		symbol_name_index = read_int(reader);
        symbol_name = read_id(reader);
        print();
	}
}
