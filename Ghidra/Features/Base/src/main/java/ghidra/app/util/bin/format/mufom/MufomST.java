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
import ghidra.app.util.bin.format.mufom.MufomHeader.MufomAbsCode;
import ghidra.app.util.bin.format.mufom.MufomHeader.MufomAbsData;
import ghidra.util.Msg;

/*
 * 10.2 ST (section type) Command
 *
 * ST-command → “ST” section-number (“,” section-type)* (“,” section-name)? “.”
 * section-number → hexnumber
 * section-type → letter
 * section-name → char-string
 *
 * ${E6}{n1}{l}[Id][n2][n3][n4]
 */
public class MufomST extends MufomRecord {
	public static final String NAME = "ST";
	public static final int record_type = MufomType.MUFOM_CMD_ST;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long section_number = -1;
	public long section_type = -1;
	public String section_name = null;
	private MufomAS as = null;
	private MufomAbsCode code = null;
	private MufomAbsData data = null;
	public long n2 = -1;
	public long n3 = -1;
	public long n4 = -1;

	private void print() {
		String msg = NAME + " : " + section_number + " " + section_name.length() + " '" + section_name + "' (" + 
				n2 +", " + n3 + ", " + n4 + ")";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomST(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		hexdump(reader, record_offset, 0x20);
		read_record_type(reader, record_type, record_subtype, NAME);

		section_number = read_int(reader);
		if (0 == section_number) {
			Msg.info(this, "Bad section");
			if (do_debug) hexdump(reader, record_offset, 0x10);
			throw new IOException();
		}

		// if section start address is an obsolute number, section is absolute, else relocatable
		// if not yet known, its relocatable
		
		as = new MufomAS(reader);

		section_name = read_opt_id(reader);

		//TODO  what is this
		n2 = read_int(reader);
		n3 = read_int(reader);
		n4 = read_int(reader);

		print();
	}
}
