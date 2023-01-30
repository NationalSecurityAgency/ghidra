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
 * Section Base Address (ASL)
 *
 * AS-command → “AS” MUFOM-variable “,” expression “,”
 *
 * L-variable → “L” section-number?
 * section-number → hexnumber
 *
 * {$E2}{$CC}{n1}{n2}
 */
public class MufomASL extends MufomRecord {
	public static final String NAME = "ASL";
	public static final int record_type = MufomType.MUFOM_CMD_AS;
	public static final int record_subtype = MufomType.MUFOM_ID_L;
	public long record_start = -1;
	public long section_number = -1;
	public long section_base_address = -1;

	private void print() {
		String msg = NAME + ": " + section_number + " 0x" + Long.toHexString(section_base_address);
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomASL(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		section_number = read_int(reader);
		section_base_address = read_int(reader);
		print();
		hexdump(reader, record_start, 0x20);
	}
}
