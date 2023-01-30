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
 * 8.4 AD (address descriptor) Command
 *
 * AD-command → “AD” bits-per-MAU (“,” MAUs-per-address) (“,” order)? )? “.”
 * bits-per-MAU → hexnumber
 * MAUs-per-address → hexnumber
 * order → “L” | “M”
 *
 * {$EC}{8){4}{$CC}
 */
public class MufomAD extends MufomRecord {
	public static final String NAME = "AD";
	public static final int record_type = MufomType.MUFOM_CMD_AD;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long bits_per_mau = -1;
	public long maus_per_address = -1;
	public int order = -1;

	private void print() {
		String msg = NAME + ": " + bits_per_mau + " " + maus_per_address;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomAD(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		bits_per_mau = read_int(reader);
		maus_per_address = read_int(reader);
		order = read_opt_char(reader);
		if (MufomType.MUFOM_ID_L == order) {
			//TODO  little endian
		} else if (MufomType.MUFOM_ID_M == order) {
			//TODO  big endian
		} else {
			//TODO  unknown
			Msg.info(this, "Unknown endianess");
			reader.setPointerIndex(reader.getPointerIndex() - 1);
		}
		print();
	}
}
