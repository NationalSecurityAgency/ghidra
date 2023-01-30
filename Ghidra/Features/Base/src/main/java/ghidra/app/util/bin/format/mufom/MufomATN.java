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
 * Attribute Records (ATN)
 *
 * AT-command → “AT” variable “,” type-table-entry (“,” lex-level (“,” hexnumber)* )? “.”
 * variable → I-variable | N-variable | X-variable
 * type-table-entry → hexnumber
 * lex-level → hexnumber
 *
 * N-variable → “N” hexnumber
 *
 * {$F1}{$CE}{n1}{n2}{n3}[x1][x2][Id]
 */
public class MufomATN extends MufomRecord {
	public static final String NAME = "ATN";
	public static final int record_type = MufomType.MUFOM_CMD_AT;
	public static final int record_subtype = MufomType.MUFOM_ID_N;
	public long record_start = -1;
	public long symbol_name_index = -1;
	public long attribute_definition = -1;
    public String id = null;
    public long x1 = -1;
    public long x2 = -1;
    public long x3 = -1;
    public long x4 = -1;
    public long x5 = -1;
    public long x6 = -1;
    public boolean has_asn = false;

    private void print() {
		String msg = NAME + ": " + symbol_name_index + " " + attribute_definition;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

    public MufomATN(BinaryReader reader) throws IOException {
    	record_start = reader.getPointerIndex();
    	read_record_type(reader, record_type, record_subtype, NAME);
		symbol_name_index = read_int(reader);

		if (read_int(reader) != 0) {
			Msg.info(this, "Bad lex-level");
			throw new IOException();
		}
		attribute_definition = read_int(reader);
        switch ((int) attribute_definition) {
        case MufomType.ieee_unknown_1_enum:
        	x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_TYPE:
            x1 = read_int(reader);
            //TODO  has_asn?  ASW0 does not
            break;
        case MufomType.MUFOM_AD_CASE:
            x1 = read_int(reader);
            //TODO  has_asn?  ASW0 does not
            break;
        case MufomType.MUFOM_AD_STATUS:
            x1 = read_int(reader);
            break;
        case MufomType.ieee_unknown_56_enum:
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_ENV:
            x1 = read_int(reader);
            break;
        case MufomType.ieee_unknown_16_enum:
            x1 = read_int(reader);
            x2 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_STATICSYMBOL:
            x1 = read_int(reader);
            x2 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_VERSION:
            x1 = read_int(reader);
            x2 = read_int(reader);
            break;
        case MufomType.ieee_unknown_7_enum:
            x1 = read_int(reader);
            x2 = read_int(reader);
            x3 = read_int(reader);
            break;
        case MufomType.ieee_execution_tool_version_enum:
            x1 = read_int(reader);
            x2 = read_int(reader);
            x3 = read_int(reader);
            break;
        case MufomType.ieee_unknown_12_enum:
            x1 = read_int(reader);
            x2 = read_int(reader);
            x3 = read_int(reader);
            x4 = read_int(reader);
            x5 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_DATETIME:
            x1 = read_int(reader); // year
            x2 = read_int(reader); // mon
            x3 = read_int(reader); // day
            x4 = read_int(reader); // hour
            x5 = read_int(reader); // min
            x6 = read_int(reader); // sec
            break;
         default:
            Msg.info(null, "Bad ATN " + symbol_name_index + " " + attribute_definition);
            throw new IOException();
         }
        print();
    }
}
