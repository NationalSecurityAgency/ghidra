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
 * 11.5 TY (type) Command
 *
 * TY_command       ::= "TY" type_table_entry [ "," parameter ]+ "."
 * type_table_entry ::= hex_number
 * parameter        ::= hex_number | N_variable | "T" type_table_entry
 *
 * {$F2}{nl}{$CE}{n2}[n3][n4]...
 */
public class MufomTY extends MufomRecord {
	public static final String NAME = "TY";
	public static final int record_type = MufomType.MUFOM_CMD_TY;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long type_index = -1;
	public long name_index = -1;

	private void print() {
		String msg = NAME + ": " + type_index +" " + name_index;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomTY(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		type_index = read_int(reader);
		if (type_index < 256) {
			Msg.info(this, "Invalid type index " + type_index);
			throw new IOException();
		}
		int record_type = read_char(reader);
		if (MufomType.MUFOM_ID_N != record_type) {
			Msg.info(null, "Expected MUFOM_ID_N, " + record_type);
		}

		name_index = read_int(reader);

		// variable number of fields
		// D-7:  19
		// D-8:

		print();
	}
}
