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
 * 12. AS (assignment) Command
 * 
 * AS_command ::= "AS" MUFOM_variable "," expression "."
 *
 * {$C1}{$D3}
 */
public class MufomAS extends MufomRecord {
	public static final String NAME = "AS";
	public static final int record_type = MufomType.MUFOM_ID_A;
	public static final int record_subtype = MufomType.MUFOM_ID_S;
	public long record_start = -1;

	public MufomAS(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		int section_type = -1;
		boolean parse_section_type = true;
		while (parse_section_type) {
			section_type = read_char(reader);
			switch (section_type) {
			case MufomType.MUFOM_ID_W:
				/* Access: writable (RAM)  This is default if no access attribute is found */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - writable");
				//TODO
				break;
			case MufomType.MUFOM_ID_R:
				/* Access: read only (ROM) */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - read only");
				//TODO
				break;
			case MufomType.MUFOM_ID_X:
				/* Access: Execute only */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - execute only");
				//TODO
				break;
			case MufomType.MUFOM_ID_Z:
				/* Access: zero page */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - zero page");
				//TODO
				break;
			case MufomType.MUFOM_ID_A:
				/* Access: Abs.  There shall be an assignment to the L-variable */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - absolute");
				//TODO
				break;
			case MufomType.MUFOM_ID_E:
				/* Overlap: Equal.  Error if lengths differ */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - equal");
				//TODO
				break;
			case MufomType.MUFOM_ID_M:
				/* Overlap: Max.  Use largest length encountered */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - max");
				//TODO
				break;
			case MufomType.MUFOM_ID_U:
				/* Overlap: Unique.  Name should be unique */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - unique");
				//TODO
				break;
			case MufomType.MUFOM_ID_C:
				/* Overlap: Cumulative.  Concatenate sections */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - cumulative");
				//TODO
				break;
			case MufomType.MUFOM_ID_S:
				/* Overlap: Separate.  No connection between sections */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - separate");
				//TODO
				break;
			case MufomType.MUFOM_ID_N:
				/* Allocate: Now.  This is normal case */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - now");
				//TODO
				break;
			case MufomType.MUFOM_ID_P:
				/* Allocate: Postpone.  re-locator must allocate after all 'now' sections */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - postpone");
				//TODO
				break;
			case MufomType.MUFOM_ID_F:
				/* Overlap: Not filled.  not filled or cleared */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - postpone");
				//TODO
				break;
			case MufomType.MUFOM_ID_Y:
				/* Access: Addressing mode.  section must be located in addressing mode num */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - postpone");
				//TODO
				break;
			case MufomType.MUFOM_ID_B:
				/* Access: blank.  must be initialized to '0' */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - postpone");
				//TODO
				break;
			case MufomType.MUFOM_ID_I:
				/* Access: initialize.  must be initialized in rom */
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - postpone");
				//TODO
				break;
			default:
				if (do_debug) Msg.info(this, String.format("%08x ", reader.getPointerIndex()) + " - DONE " + section_type);
				parse_section_type = false;
				reader.setPointerIndex(reader.getPointerIndex() - 1);
				break;
			}
		}
	}
}
