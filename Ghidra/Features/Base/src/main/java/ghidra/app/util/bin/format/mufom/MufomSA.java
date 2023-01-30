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
 * 10.3 SA (section alignment) Command
 *
 * SA-command → “SA” section-number “,” MAU-boundary? ("," page-size)? "."
 * MAU-boundary → expression
 * page-size → expression
 *
 * {$E7}{n1}{n2}
 */
public class MufomSA extends MufomRecord {
	public static final String NAME = "SA";
	public static final int record_type = MufomType.MUFOM_CMD_SA;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long section_number = -1;
	public long mau_boundary = -1;
	public long page_size = -1;

	private void print() {
		String msg = NAME + ": " + section_number + " " + mau_boundary + " " + page_size;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomSA(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		section_number = read_int(reader);
		mau_boundary = read_int(reader);
		page_size = read_int(reader);
		print();
	}
}
