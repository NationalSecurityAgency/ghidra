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
 * Block End (BE)
 *
 * {$F9}[{n1}]
 */
public class MufomBE extends MufomRecord {
	public static final String NAME = "BE";
	public static final int record_type = MufomType.MUFOM_CMD_LN;
	public static final int record_subtype = -1;
	public long record_start = -1;

	private void print() {
		String msg = NAME;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBE(BinaryReader reader, int bb) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		switch (bb) {
		case MufomType.MUFOM_BB4:
		case MufomType.MUFOM_BB6:
			//TODO Expression defining the ending address of the function (in minimum address units)
			Msg.info(this, "BE 4 or 6");
			throw new IOException();
			//break;
		case MufomType.MUFOM_BB11:
			//TODO Expression defining the size in minimum address units of the module section
			Msg.info(this, "BE 11");
			throw new IOException();
			//break;
		default:
			break;
		}
		print();
	}
}
