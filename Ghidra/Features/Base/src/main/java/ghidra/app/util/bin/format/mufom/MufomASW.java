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
 * Assign Value to Variable W
 *
 * AS-command → “AS” MUFOM-variable “,” expression “,”
 *
 * W-variable → “W” hexnumber
 *
 * {$E2}{$D7}{00}{n}
 * {$E2}{$D7}{01}{n}
 * {$E2}{$D7}{02}{n}
 * {$E2}{$D7}{03}{n}
 * {$E2}{$D7}{04}{n}
 * {$E2}{$D7}{05}{n}
 * {$E2}{$D7}{06}{n}
 * {$E2}{$D7}{07}{n}
 */
public class MufomASW extends MufomRecord {
	public static final String NAME = "ASW";
	public static final int record_type = MufomType.MUFOM_CMD_AS;
	public static final int record_subtype = MufomType.MUFOM_ID_W;
	public long record_start = -1;
	public long asw_index = -1;
	public long asw_offset = -1;

	private void print() {
		String msg = NAME + ": " + asw_index + " " + Long.toHexString(asw_offset);
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomASW(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		asw_index = read_int(reader);
		if (asw_index < 0 || asw_index > 7) {
			Msg.info(this, "Bad ASW index");
			throw new IOException();
		}
		asw_offset = read_int(reader);
		if (asw_offset < 0 || asw_offset > reader.length()) {
			Msg.info(this, "Bad ASW offset");
			throw new IOException();
		}
		print();
	}
}
