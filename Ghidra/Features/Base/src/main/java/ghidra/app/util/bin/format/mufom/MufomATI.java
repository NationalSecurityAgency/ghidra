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
 * Attribute Records (ATI)
 *
 * AT-command → “AT” variable “,” type-table-entry (“,” lex-level (“,” hexnumber)* )? “.”
 * variable → I-variable | N-variable | X-variable
 * type-table-entry → hexnumber
 * lex-level → hexnumber
 *
 * I-variable → “I” hexnumber
 *
 * {$F1}{$C9}{n1}{n2}{n3}{n4}
 */
public class MufomATI extends MufomRecord {
	public static final String NAME = "ATI";
	public static final int record_type = MufomType.MUFOM_CMD_AT;
	public static final int record_subtype = MufomType.MUFOM_ID_I;
	public long record_start = -1;
	public long symbol_name_index = -1;
	public long symbol_type_index = -1;
	public long attribute_definition = -1;
	public long static_symbol = -1;
	public long number_of_elements = -1;

	private void print() {
		String msg = NAME + ": " + symbol_name_index + " " + symbol_type_index + " " +
				attribute_definition + " " + number_of_elements;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomATI(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		symbol_name_index = read_int(reader);
		symbol_type_index = read_int(reader);
		switch ((int) symbol_type_index) {
        case MufomType.MUFOM_BUILTIN_UNK:
        	Msg.info(this, "TYPE: UNK");
        	break;
        case MufomType.MUFOM_BUILTIN_V:
        	Msg.info(this, "TYPE: V");
        	break;
        case MufomType.MUFOM_BUILTIN_B:
        	Msg.info(this, "TYPE: B");
        	break;
        case MufomType.MUFOM_BUILTIN_C:
        	Msg.info(this, "TYPE: C");
            break;
        case MufomType.MUFOM_BUILTIN_H:
        	Msg.info(this, "TYPE: H");
            break;
        case MufomType.MUFOM_BUILTIN_I:
        	Msg.info(this, "TYPE: I");
            break;
        case MufomType.MUFOM_BUILTIN_L:
        	Msg.info(this, "TYPE: L");
            break;
        case MufomType.MUFOM_BUILTIN_M:
        	Msg.info(this, "TYPE: M");
            break;
        case MufomType.MUFOM_BUILTIN_F:
        	Msg.info(this, "TYPE: F");
            break;
        case MufomType.MUFOM_BUILTIN_D:
        	Msg.info(this, "TYPE: D");
            break;
        case MufomType.MUFOM_BUILTIN_K:
        	Msg.info(this, "TYPE: K");
            break;
        case MufomType.MUFOM_BUILTIN_J:
        	Msg.info(this, "TYPE: J");
            break;
        case MufomType.MUFOM_BUILTIN_PUNK:
        	Msg.info(this, "TYPE: PUNK");
            break;
        case MufomType.MUFOM_BUILTIN_PV:
        	Msg.info(this, "TYPE: PV");
            break;
        case MufomType.MUFOM_BUILTIN_PB:
        	Msg.info(this, "TYPE: PB");
        	break;
        case MufomType.MUFOM_BUILTIN_PC:
        	Msg.info(this, "TYPE: PC");
        	break;
        case MufomType.MUFOM_BUILTIN_PH:
        	Msg.info(this, "TYPE: PH");
        	break;
        case MufomType.MUFOM_BUILTIN_PI:
        	Msg.info(this, "TYPE: PI");
        	break;
        case MufomType.MUFOM_BUILTIN_PL:
        	Msg.info(this, "TYPE: PL");
            break;
        case MufomType.MUFOM_BUILTIN_PM:
        	Msg.info(this, "TYPE: PM");
            break;
        case MufomType.MUFOM_BUILTIN_PF:
        	Msg.info(this, "TYPE: PF");
            break;
        case MufomType.MUFOM_BUILTIN_PD:
        	Msg.info(this, "TYPE: PD");
            break;
        case MufomType.MUFOM_BUILTIN_PK:
        	Msg.info(this, "TYPE: PK");
        	break;
        default:
        	Msg.info(this, "Bad type " + symbol_type_index);
        	throw new IOException();
        }

		attribute_definition = read_int(reader);
		if (MufomType.MUFOM_AD_STATICSYMBOL != attribute_definition) {
			Msg.info(this, "unkown attribute_definition " + attribute_definition);
			hexdump(reader, record_offset, 0x10);
		}
		static_symbol = read_int(reader);
		
		if (MufomType.MUFOM_BUILTIN_UNK != symbol_type_index) {
			number_of_elements = read_int(reader);
		}
		print();
	}
}
