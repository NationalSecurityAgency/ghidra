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
 * Set Current PC, absolute code (ASP)
 *
 * AS-command → “AS” MUFOM-variable “,” expression “,”
 *
 * P-variable → “P” section-number?
 * section-number → hexnumber
 */
public class MufomASP extends MufomRecord {
	public static final String NAME = "ASP";
	public static final int record_type = MufomType.MUFOM_CMD_AS;
	public static final int record_subtype = MufomType.MUFOM_ID_P;
	public long record_start = -1;
	public long section_index = -1;
	public long current_pc = -1;

	public static boolean check(BinaryReader reader) throws IOException {
		long offset = reader.getPointerIndex();
		if (record_type == reader.readUnsignedByte(offset + 0) &&
				record_subtype == reader.readUnsignedByte(offset + 1)) {
			return true;
		}
		return false;
	}

	private void print() {
		String msg = NAME + ": " + section_index + " " + Long.toHexString(current_pc);
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}
	public MufomASP(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		section_index = read_int(reader);
		current_pc = read_int(reader);
		print();
	}
}
