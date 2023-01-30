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

public class MufomBB extends MufomRecord {
	public static final String NAME = "BB";
	public static final int record_type = MufomType.MUFOM_CMD_SC;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long begin_block = -1;
	public long block_size = -1;
	public MufomBB bb1 = null;
	public MufomBB bb2 = null;
	public MufomBB bb3 = null;
	public MufomBB bb4 = null;
	public MufomBB bb5 = null;
	public MufomBB bb6 = null;
	public MufomBB bb10 = null;
	public MufomBB bb11 = null;

	public long block_start = -1;
	public long block_end = -1;

	private void print() {
		String msg = NAME + ": " + begin_block + " 0x" + Long.toHexString(block_size) + " " +
				Long.toHexString(record_start) + " " + Long.toHexString(block_end) + " " +
				Long.toHexString(block_end - record_start);
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);

		begin_block = read_int(reader);
		block_size = read_int(reader);
		switch ((int) begin_block) {
		case MufomType.MUFOM_BB1:
			new MufomBB1(reader);
			break;
		case MufomType.MUFOM_BB2:
			new MufomBB2(reader);
			break;
		case MufomType.MUFOM_BB3:
			new MufomBB3(reader);
			break;
		case MufomType.MUFOM_BB4:
			new MufomBB4(reader);
			break;
		case MufomType.MUFOM_BB5:
			new MufomBB5(reader);
			break;
		case MufomType.MUFOM_BB6:
			new MufomBB6(reader);
			break;
		case MufomType.MUFOM_BB10:
			new MufomBB10(reader);
			break;
		case MufomType.MUFOM_BB11:
			new MufomBB11(reader);
			break;
		default:
			break;
		}
		block_end = reader.getPointerIndex();
		print();
	}
}
