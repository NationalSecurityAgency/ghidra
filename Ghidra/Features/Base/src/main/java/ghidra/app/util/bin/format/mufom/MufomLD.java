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
 * 13.1 LD (load) Command
 *
 * LD-command → “LD” load-constant + “.”
 * load-constant → hexdigit +
 *
 * {$ED}{n1}{...}
 */
public class MufomLD extends MufomRecord {
	public static final String NAME = "LD";
	public static final int record_type = MufomType.MUFOM_CMD_LD;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long data_bytes_offset;
	public long address_units;

	private void print() {
		String msg = NAME + ": " + data_bytes_offset + " " + address_units;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomLD(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		address_units = read_int(reader);
		if (address_units < 1 || address_units > 127) {
			Msg.info(this, "bad units");
			throw new IOException();
		}
		data_bytes_offset = reader.getPointerIndex();
		reader.setPointerIndex(data_bytes_offset + address_units);
		// OR
		// bytes = reader.readNextByteArray((int) address_units);

		print();
	}
}
