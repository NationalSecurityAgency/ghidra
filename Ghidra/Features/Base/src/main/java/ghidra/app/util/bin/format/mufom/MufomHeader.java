/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.mufom;

import java.io.IOException;
import java.util.Calendar;
import java.util.function.Consumer;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;

public class MufomHeader {
	public final static String MUFOM_NAME = "IEEE-695-MUFOM";
	public BinaryReader reader = null;
	private Consumer<String> errorConsumer;
	private boolean do_debug = false;

	public MufomHeaderPart hdr = null;
	public MufomADExtension asw0 = null;
	public MufomEnvironment asw1 = null;
	public MufomSectionDefinition asw2 = null;
	public MufomExternal asw3 = null;
	public MufomDebugInformation asw4 = null;
	public MufomData asw5 = null;
	public MufomTrailer asw6 = null;
	public MufomEnd asw7 = null;

	public MufomHeader(ByteProvider bp, Consumer<String> errorConsumer) throws IOException {
		reader = new BinaryReader(bp, false);
		reader.setPointerIndex(0);
		Msg.trace(this, String.format("%08x-%08x ", 0, reader.length()) + "PARSE MUFOM");
        this.errorConsumer = errorConsumer != null ? errorConsumer : msg -> {
			/* no logging if errorConsumer was null */
		};
        parse();
    }

	public static String getName() {
		return MUFOM_NAME;
	}

	private void parse() throws IOException {
		hdr = new MufomHeaderPart();
		if (hdr.asw_offset[0] > 0) {
			MufomADExtension tmp = null;
			reader.setPointerIndex(hdr.asw_offset[0]);
			while (hdr.asw_end[0] > reader.getPointerIndex()) {
				tmp = new MufomADExtension(tmp);
				if (null == asw0)
					asw0 = tmp;
			}
		}
		if (hdr.asw_offset[1] > 0) {
			MufomEnvironment tmp = null;
			reader.setPointerIndex(hdr.asw_offset[1]);
			while (hdr.asw_end[1] > reader.getPointerIndex()) {
				tmp = new MufomEnvironment(tmp);
				if (null == asw1)
					asw1 = tmp;
			}
		}
		if (hdr.asw_offset[2] > 0) {
			MufomSectionDefinition tmp = null;
			reader.setPointerIndex(hdr.asw_offset[2]);
			while (hdr.asw_end[2] > reader.getPointerIndex()) {
				tmp = new MufomSectionDefinition(tmp);
				if (null == asw2)
					asw2 = tmp;
			}
		}

		if (hdr.asw_offset[3] > 0) {
			MufomExternal tmp = null;
			reader.setPointerIndex(hdr.asw_offset[3]);
			while (hdr.asw_end[3] > reader.getPointerIndex()) {
				tmp = new MufomExternal(tmp);
				if (null == asw3)
					asw3 = tmp;
			}
		}
		//TODO  This section is too complicated for now
//		if (hdr.asw_offset[4] > 0) {
//          MufomDebugInformation tmp = null;
//			reader.setPointerIndex(hdr.asw_offset[4]);
//			while (hdr.asw_end[4] > reader.getPointerIndex()) {
//				tmp = new MufomDebugInformation(tmp);
//              if (null == asw4)
//                  asw4 = tmp;
//			}
//		}
		if (hdr.asw_offset[5] > 0) {
			reader.setPointerIndex(hdr.asw_offset[5]);
			MufomData tmp = null;
			while (hdr.asw_end[5] > reader.getPointerIndex()) {
				tmp = new MufomData(tmp);
				if (null == asw5)
					asw5 = tmp;
			}
		}
		if (hdr.asw_offset[6] > 0) {
			reader.setPointerIndex(hdr.asw_offset[6]);
			asw6 = new MufomTrailer();
		}
		if (hdr.asw_offset[7] > 0) {
			reader.setPointerIndex(hdr.asw_offset[7]);
			asw7 = new MufomEnd();
		}
	}

	public boolean valid() {
		if (null == hdr) {
			Msg.error(this, "invalid header start");
			return false;
		} else if (hdr.asw_offset[0] > 0 && null == asw0) {
			Msg.error(this, "invalid ASW0");
			return false;
		} else if (hdr.asw_offset[1] > 0 && null == asw1) {
			Msg.error(this, "invalid ASW1");
			return false;
		} else if (hdr.asw_offset[2] > 0 && null == asw2) {
			Msg.error(this, "invalid ASW2");
			return false;
		} else if (hdr.asw_offset[3] > 0 && null == asw3) {
			Msg.error(this, "invalid ASW3");
			return false;
//		} else if (hdr.asw_offset[4] > 0 && null == asw4) {
//			Msg.error(this, "invalid ASW4");
//			return false;
		} else if (hdr.asw_offset[5] > 0 && null == asw5) {
			Msg.error(this, "invalid ASW5");
			return false;
		} else if (hdr.asw_offset[6] > 0 && null == asw6) {
			Msg.error(this, "invalid ASW6");
			return false;
		} else if (null == asw7) {
			Msg.error(this, "invalid ASW7");
			return false;
		}
		return true;
	}

	public boolean is_little() {
		return (MufomType.MUFOM_ID_L == hdr.ad.order);
	}

	public boolean is_big() {
		return (MufomType.MUFOM_ID_M == hdr.ad.order);
	}

	public String machine() {
		return hdr.mb.target_machine_configuration;
	}

	/*
	 * 8.1 MB (module begin) Command
	 *
	 * MB-command → “MB” target-machine-configuration (“,” module-name)? “.”
	 * target-machine-configuration → identifier
	 * module-name → char-string
	 *
	 * {$E0}{Id1}{Id2}
	 */
	public class MufomMB extends MufomRecord {
		private final String NAME = "MB";
		private String target_machine_configuration = null;
		public String module_name = null;

		private void print() {
			String msg = NAME + ": " + target_machine_configuration + " " + module_name;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}
		public MufomMB(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_MB != read_char(reader)) {
				Msg.info(this, "Bad MB");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			target_machine_configuration = read_id(reader);
			module_name = read_opt_id(reader);
			print();
		}
	}

	/*
	 * 8.2 ME (module end) Command
	 *
	 * ME-command → “ME.”
	 *
	 * {$E1}
	 */
	public class MufomME extends MufomRecord {
		private final String NAME = "ME";

		private void print() {
			String msg = NAME;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomME(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_ME != read_char(reader)) {
				Msg.info(this, "bad ME");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			print();
		}
	}

	/*
	 * 8.3 DT (date and time of creation) Command
	 *
	 * DT-command → "DT" digit* “.”
	 */
	public class MufomDT extends MufomRecord {
		private final String NAME = "DT";
		public MufomDT(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

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
		private final String NAME = "AD";
		public long bits_per_mau = -1;
		public long maus_per_address = -1;
		private int order = -1;

		private void print() {
			String msg = NAME + ": " + bits_per_mau + " " + maus_per_address;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomAD(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AD != read_char(reader)) {
				Msg.info(this, "Bad AD");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			bits_per_mau = read_int(reader);
			maus_per_address = read_int(reader);
			order = read_opt_char(reader);
			if (MufomType.MUFOM_ID_L == order) {
				//TODO  little endian
			} else if (MufomType.MUFOM_ID_M == order) {
				//TODO  big endian
			} else if (-1 == order) {
				//TODO  unknown
				Msg.info(this, "Unknown endianess");
			} else {
				Msg.info(this, "Bad endian " + order);
				throw new IOException();
			}
			print();
		}
	}


	/*
	 * 9.1 Comments
	 */
	public class MufomCO extends MufomRecord {
		private final String NAME = "CO";
		public MufomCO(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 9.2 CS (checksum) Command
	 */
	public class MufomCS extends MufomRecord {
		private final String NAME = "CS";
		public MufomCS(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 10.1 SB (section begin) Command
	 *
	 * SB-command → “SB” section-number “.”
	 * section-number → hexnumber
	 *
	 * {$E5}{n1}
	 */
	public class MufomSB extends MufomRecord {
		private final String NAME = "SB";
		public long section_number = -1;

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (MufomType.MUFOM_CMD_SB == reader.readUnsignedByte(offset + 0)) {
				return true;
			}
			return false;
		}

		private void print() {
			String msg = NAME + ": " + section_number;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomSB(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_SB != read_char(reader)) {
				Msg.info(this, "bad SB");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			section_number = read_int(reader);
			print();
		}
	}

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
		private final String NAME = "ST";
		public long section_number = -1;
		public String section_name = null;
		private MufomAS as = null;
		private MufomAbsCode code = null;
		private MufomAbsData data = null;
		private long n2 = -1;
		private long n3 = -1;
		private long n4 = -1;

		private void print() {
			String msg = NAME + ": " + section_number + " " + section_name + " " + n2 +" "+n3+" "+n4;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomST(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_ST != read_char(reader)) {
				//TODO  "if no ST-command is given for a section, its type is absolute (A)"
				Msg.info(this, "Bad ST");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}

			section_number = read_int(reader);
			if (0 == section_number) {
				Msg.info(this, "Bad section");
				throw new IOException();
			}

			// one section type: AS, ASP, or ASD
			if (MufomAbsCode.check(reader)) {
				code = new MufomAbsCode(reader);
			} else if (MufomAbsData.check(reader)) {
				data = new MufomAbsData(reader);
			} else {
				as = new MufomAS(reader);
			}

			section_name = read_opt_id(reader);

			//TODO  what is this
			n2 = read_int(reader);
			n3 = read_int(reader);
			n4 = read_int(reader);

			print();
		}
	}

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
		private final String NAME = "SA";
		public long section_number = -1;
		public long mau_boundary = -1;
		public long page_size = -1;

		private void print() {
			String msg = NAME + ":" + section_number + " " + mau_boundary + " " + page_size;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomSA(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_SA != read_char(reader)) {
				Msg.info(this, "Bad SA");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			section_number = read_int(reader);
			mau_boundary = read_int(reader);
			page_size = read_int(reader);
			print();
		}
	}

	/*
	 * 11.1 NI (name of internal symbol) Command
	 *
	 * NI-command → “N” I-variable “,” ext-def-name “.”
	 * I-variable → “I” hexnumber
	 * ext-def-name → char-string
	 *
	 * {$E8}{n}{Id}
	 */
	public class MufomNI extends MufomRecord {
		private final String NAME = "NI";
		public long symbol_name_index = -1;
		public String symbol_name = null;

		private void print() {
			String msg = NAME;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomNI(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_NI != read_char(reader)) {
				Msg.info(this, "Bad NI");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			symbol_name_index = read_int(reader);
			symbol_name = read_id(reader);
			print();
		}
	}

	/*
	 * 11.2 NX (name of external symbol) Command
	 */
	public class MufomNX extends MufomRecord {
		private final String NAME = "NX";
		public MufomNX(BinaryReader reader) throws IOException {
			//TODO  is it a $E8 typo or is this $B8?
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 11.3 NN (name) Command
	 *
	 * NN-command → “N” N-variable “,” name “.”
	 * N-variable → “N” hexnumber
	 * name → char-string
	 *
	 * {$F0}{n1}{Id}
	 */
	public class MufomNN extends MufomRecord {
		private final String NAME = "NN";
		public long symbol_name_index = -1;
		public String symbol_name = null;

		private void print() {
			String msg = NAME + ": '" + symbol_name + "' " + symbol_name_index;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomNN(BinaryReader reader, boolean must) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (!must && omit_cmd(reader)) {
				return;
			}
			if (MufomType.MUFOM_CMD_NN != read_char(reader)) {
				Msg.info(this, "Bad NN");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}

			symbol_name_index = read_int(reader);
	        symbol_name = read_id(reader);
	        print();
		}
	}

	/*
	 * 11.4 AT (attributes) Command
	 */
	public class MufomAT extends MufomRecord {
		private final String NAME = "AT";
		public MufomAT(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 11.5 TY (type) Command
	 *
	 * TY_command       ::= "TY" type_table_entry [ "," parameter ]+ "."
	 * type_table_entry ::= hex_number
	 * parameter        ::= hex_number | N_variable | "T" type_table_entry
	 *
	 * {$F2}{nl}{$CE}{n2}[n3][n4]...
	 */
	public class MufomTY extends MufomRecord {
		private final String NAME = "TY";
		public long type_index = -1;
		public long name_index = -1;

		private void print() {
			String msg = NAME + ": " + type_index +" " + name_index;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomTY(BinaryReader reader, boolean must) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (!must && omit_cmd(reader)) {
				return;
			}
			if (MufomType.MUFOM_CMD_TY != read_char(reader)) {
				Msg.info(this, "Bad TY");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			type_index = read_int(reader);
			if (type_index < 256) {
				Msg.info(this, "Invalid type index " + type_index);
				throw new IOException();
			}
			int record_type = read_char(reader);
			if (MufomType.MUFOM_ID_N != record_type) {
				Msg.info(null, "Expected MUFOM_ID_N, " + record_type);
			}

			name_index = read_int(reader);

			// variable number of fields
			// D-7:  19
			// D-8:

			print();
		}
	}

	/*
	 * 12. AS (assignment) Command
	 *
	 * {$C1}{$D3}
	 */
	public class MufomAS extends MufomRecord {
		private final String NAME = "AS";

		public MufomAS(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_ID_A != read_char(reader)) {
				Msg.info(this, "bad A");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_S != read_char(reader)) {
				Msg.info(this, "bad S");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}

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
					/* Allocate: Postpone.  relocator must allocate after all 'now' sections */
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

	/*
	 * 13.1 LD (load) Command
	 *
	 * LD-command → “LD” load-constant + “.”
	 * load-constant → hexdigit +
	 *
	 * {$ED}{n1}{...}
	 */
	public class MufomLD extends MufomRecord {
		private final String NAME = "LD";
		private long data_bytes_offset;
		private long address_units;

		private void print() {
			String msg = NAME + ": " + data_bytes_offset + " " + address_units;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomLD(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_LD != read_char(reader)) {
				Msg.info(this, "bad LD");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}

			address_units = read_int(reader);
			if (address_units < 1 || address_units > 127) {
				Msg.info(this, "bad units");
				throw new IOException();
			}
			data_bytes_offset = reader.getPointerIndex();
			reader.setPointerIndex(data_bytes_offset + address_units);
			// OR
			// bytes = reader.readNextByteArray((int) address_units);

			print();
		}
	}

	/*
	 * 13.2 IR (initialize relocation base) Command
	 */
	public class MufomIR extends MufomRecord {
		private final String NAME = "IR";
		public MufomIR(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 13.3 LR (load relocate) Command
	 */
	public class MufomLR extends MufomRecord {
		private final String NAME = "LR";
		public MufomLR(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 13.4 RE (replicate) Command
	 *
	 * RE-command → “RE” expression “.”
	 */
	public class MufomRE extends MufomRecord {
		private final String NAME = "RE";
		public long repeat = -1;

		private void print() {
			String msg = NAME;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomRE(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_RE != read_char(reader)) {
				Msg.info(this, "bad RE");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			repeat = read_int(reader);
			print();
		}
	}

	/*
	 * 14.1 RI (retain internal symbol) Command
	 */
	public class MufomRI extends MufomRecord {
		private final String NAME = "RI";
		public MufomRI(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 14.2 WX (weak external symbol) Command
	 */
	public class MufomWX extends MufomRecord {
		private final String NAME = "WX";
		public MufomWX(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 15.1 LI (Specify Default Library Search List) Command
	 */
	public class MufomLI extends MufomRecord {
		private final String NAME = "Li";
		public MufomLI(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	/*
	 * 15.2 LX (library external) Command
	 */
	public class Mufom extends MufomRecord {
		private final String NAME = "LX";
		public Mufom(BinaryReader reader) throws IOException {
			Msg.info(this, "unimplemented " + NAME);
			throw new IOException();
		}
	}

	public class MufomBB extends MufomRecord {
		private final String NAME = "BB";
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

		private long block_start = -1;
		private long block_end = -1;

		private void print() {
			String msg = NAME + ": " + begin_block + " 0x" + Long.toHexString(block_size) + " " +
					Long.toHexString(block_start) + " " + Long.toHexString(block_end) + " " +
					Long.toHexString(block_end - block_start);
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			block_start = reader.getPointerIndex();
			if (MufomType.MUFOM_CMD_SC != read_char(reader)) {
				Msg.info(this, "bad SC");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}

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

	/*
	 * Type definitions local to a module.
	 */
	public class MufomBB1 extends MufomRecord {
		public String module_name = null;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB1(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB1");
			if (0 != read_int(reader)) {
				Msg.info(this, "Bad block size");
				throw new IOException();
			}
			module_name = read_id(reader);
			print();
		}
	}

	/*
	 * Global type definitions.
	 */
	public class MufomBB2 extends MufomRecord {
		public String module_name = null;

		private void print() {
			String msg = "BB2: '" + module_name + "'";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB2(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB2");
			module_name = read_id(reader);
			print();
		}
	}

	/*
	 * A module. A non-separable unit of code, usually the result of a
	 * single compilation, i.e. the symbols associated with a COFF
	 * .file symbol.
	 */
	public class MufomBB3 extends MufomRecord {
		public String module_name = null;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB3(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB3");
			module_name = read_id(reader);
			print();
		}
	}

	/*
	 * A global subprogram.
	 */
	public class MufomBB4 extends MufomRecord {
		public String function_name = null;
		public long type_index = -1;
		public long code_block_address = -1;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB4(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB4");
			function_name = read_id(reader);
			if (0 != read_int(reader)) {
				Msg.info(this, "Bad stack space");
				throw new IOException();
			}
			type_index = read_int(reader);
			code_block_address = read_int(reader);
			print();
		}
	}

	/*
	 * A source file line number block.
	 */
	public class MufomBB5 extends MufomRecord {
		public String source_filename = null;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB5(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB5");
			source_filename = read_id(reader);
			print();
		}
	}

	/*
	 * A local (static) subprogram.
	 */
	public class MufomBB6 extends MufomRecord {
		public String function_name = null;
		public long stack_space = -1;
		public long type_index = -1;
		public long code_block_offset = -1;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB6(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB6");
			if (0 != read_int(reader)) {
				Msg.info(this, "Bad block size");
				throw new IOException();
			}
			function_name = read_id(reader);
			stack_space = read_int(reader);
			type_index = read_int(reader);
			code_block_offset = read_int(reader);
			print();
		}
	}

	/*
	 * An assembler debugging information block.
	 */
	public class MufomBB10 extends MufomRecord {
		public String source_filename = null;
		public long tool_type = -1;
		public String version = null;
		public Calendar date;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB10(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB10");
			source_filename = read_id(reader);
			String zero = read_id(reader);
			if (zero.length() != 0) {
				Msg.info(this, "Bad zero");
				throw new IOException();
			}
			tool_type = read_int(reader);
			if (210 == tool_type) {

			} else if (209 == tool_type) {

			} else {
				Msg.info(this, "bad tool");
				throw new IOException();
			}
			version = read_id(reader);

			int year = (int) read_int(reader);
			int month = (int) read_int(reader);
			int day = (int) read_int(reader);
			int hour = (int) read_int(reader);
			int minute = (int) read_int(reader);
			int second = (int) read_int(reader);
			date.set(year, month, day, hour, minute, second);
			print();
		}
	}

	/*
	 * The module portion of a section.
	 */
	public class MufomBB11 extends MufomRecord {
		public long section_type = -1;
		public long section_number = -1;
		public long section_offset = -1;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBB11(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB11");
			String zero = read_id(reader);
			if (zero.length() != 0) {
				Msg.info(this, "bad zero");
				throw new IOException();
			}
			section_type = read_int(reader);
			section_number = read_int(reader);
			section_offset = read_int(reader);
			print();
		}
	}

	/*
	 * Value Records (ASN)
	 *
	 * AS-command → “AS” MUFOM-variable “,” expression “,”
	 *
	 * N-variable → “N” hexnumber
	 */
	public class MufomASN extends MufomRecord {
		private final String NAME = "ASN";
		public long symbol_name_index = -1;
		public long symbol_name_value = -1;

		private void print() {
			String msg = NAME + ": " + symbol_name_index + " " + symbol_name_value;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomASN(BinaryReader reader, boolean must) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (!must && omit_cmd(reader)) {
				return;
			}
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "Bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_N != read_char(reader)) {
				Msg.info(this, "Bad N");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			symbol_name_index = read_int(reader);
			symbol_name_value = read_int(reader);
			print();
		}
	}

	/*
	 * Compiler Id
	 *
	 * {$F1}{$CE}{n1}{0}{64}{50}{n5}{ASN1}{0}{4}[ATN1][ASN4[ASN5[ASN6[ASN7[ASN8[ASN9]]]]]]
	 */
	public class MufomCompiler extends MufomRecord {
		public MufomNN nn = null;
		public MufomATN atn = null;
		public MufomATN atn1 = null;
		public MufomASN asntool = null;
		public MufomASN asntype = null;
		public MufomASN asnsize = null;
		public MufomASN asnyear = null;
		public MufomASN asnmonth = null;
		public MufomASN asnday = null;
		public MufomASN asnhour = null;
		public MufomASN asnminute = null;
		public MufomASN asnsecond = null;

		private void print() {
			String msg = "";
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomCompiler(BinaryReader reader, boolean must) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomCompiler");
			if (!must && omit_cmd(reader)) {
				return;
			}
			nn = new MufomNN(reader, true);
			atn = new MufomATN(reader, true);
			asntool = new MufomASN(reader, true);
			asntype = new MufomASN(reader, true);
			asnsize = new MufomASN(reader, true);
			atn1 = new MufomATN(reader, false);
			asnyear = new MufomASN(reader, false);
			asnmonth = new MufomASN(reader, false);
			asnday = new MufomASN(reader, false);
			asnhour = new MufomASN(reader, false);
			asnminute = new MufomASN(reader, false);
			asnsecond = new MufomASN(reader, false);
			print();
		}
	}

	/*
	 * Section Size (ASS)
	 *
	 * AS-command → “AS” MUFOM-variable “,” expression “,”
	 *
	 * S-variable → “S” section-number?
	 * section-number → hexnumber
	 *
	 * {$E2}{$D3}{n1}{n2}
	 */
	public class MufomASS extends MufomRecord {
		private final String NAME = "ASS";
		public long section_number = -1;
		public long section_size = -1;

		private void print() {
			String msg = NAME + ": " + section_number + " " + section_size;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomASS(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "Bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_S != read_char(reader)) {
				Msg.info(this, "Bad S");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			section_number = read_int(reader);
			section_size = read_int(reader);
			print();
		}
	}

	/*
	 * Section Base Address (ASL)
	 *
	 * AS-command → “AS” MUFOM-variable “,” expression “,”
	 *
	 * L-variable → “L” section-number?
	 * section-number → hexnumber
	 *
	 * {$E2}{$CC}{n1}{n2}
	 */
	public class MufomASL extends MufomRecord {
		private final String NAME = "ASL";
		public long section_number = -1;
		public long section_base_address = -1;

		private void print() {
			String msg = NAME + ": " + section_number + " 0x" + Long.toHexString(section_base_address);
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomASL(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "Bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_L != read_char(reader)) {
				Msg.info(this, "Bad L");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			section_number = read_int(reader);
			section_base_address = read_int(reader);
			print();
		}
	}

	/*
	 * Value Records (ASI)
	 *
	 * AS-command → “AS” MUFOM-variable “,” expression “,”
	 *
	 * I-variable → “I” hexnumber
	 *
	 * {$E2}{$C9}{n1}{n2}
	 */
	public class MufomASI extends MufomRecord {
		private final String NAME = "ASI";
		public long symbol_name_index = -1;
		public long symbol_value = -1;

		private void print() {
			String msg = NAME + ": " + symbol_name_index + " " + symbol_value;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomASI(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "Bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_I!= read_char(reader)) {
				Msg.info(this, "Bad I");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			symbol_name_index = read_int(reader);
			symbol_value = read_int(reader);
			print();
		}
	}

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
		private final String NAME = "ATI";
		public long symbol_name_index = -1;
		public long symbol_type_index = -1;
		public long attribute_definition = -1;
		public long number_of_elements = -1;

		private void print() {
			String msg = NAME;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomATI(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AT != read_char(reader)) {
				Msg.info(this, "Bad AT");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_I!= read_char(reader)) {
				Msg.info(this, "Bad I");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
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
			if (MufomType.MUFOM_BUILTIN_UNK != symbol_type_index) {
				number_of_elements = read_int(reader);
			}
			print();
		}
	}

	/*
	 * Block End (BE)
	 *
	 * {$F9}[{n1}]
	 */
	public class MufomBE extends MufomRecord {
		private final String NAME = "BE";

		private void print() {
			String msg = NAME;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomBE(BinaryReader reader, int bb) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_LN != read_char(reader)) {
				Msg.info(this, "Bad BE");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
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

	/*
	 * Set Current PC, absolute code (ASP)
	 *
	 * AS-command → “AS” MUFOM-variable “,” expression “,”
	 *
	 * P-variable → “P” section-number?
	 * section-number → hexnumber
	 */
	public class MufomASP extends MufomRecord {
		private final String NAME = "ASP";
		private long section_index = -1;
		private long current_pc = -1;

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (MufomType.MUFOM_CMD_AS == reader.readUnsignedByte(offset + 0) &&
					MufomType.MUFOM_ID_P == reader.readUnsignedByte(offset + 1)) {
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
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "bad P");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_P != read_char(reader)) {
				Msg.info(this, "bad P");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			section_index = read_int(reader);
			current_pc = read_int(reader);
			print();
		}
	}

	/*
	 * Absolute Code
	 *
	 * {$C1}{$D3}{$D0}
	 */
	public class MufomAbsCode extends MufomRecord {

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (MufomType.MUFOM_ID_A == reader.readUnsignedByte(offset + 0) &&
					MufomType.MUFOM_ID_S == reader.readUnsignedByte(offset + 1) &&
							MufomType.MUFOM_ID_P == reader.readUnsignedByte(offset + 2)) {
				return true;
			}
			return false;
		}

		public MufomAbsCode(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomAbsCode");
			if (MufomType.MUFOM_ID_A != read_char(reader)) {
				Msg.info(this, "bad A");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_S != read_char(reader)) {
				Msg.info(this, "bad S");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_P != read_char(reader)) {
				Msg.info(this, "bad P");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-3, 0x10);
				throw new IOException();
			}
		}
	}

	/*
	 * Absolute Data
	 *
	 * {$C1}{$D3}{$C4}
	 */
	public class MufomAbsData extends MufomRecord {

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (MufomType.MUFOM_ID_A == reader.readUnsignedByte(offset + 0) &&
					MufomType.MUFOM_ID_S == reader.readUnsignedByte(offset + 1) &&
							MufomType.MUFOM_ID_D == reader.readUnsignedByte(offset + 2)) {
				return true;
			}
			return false;
		}

		public MufomAbsData(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomAbsData");
			if (MufomType.MUFOM_ID_A != read_char(reader)) {
				Msg.info(this, "bad A");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_S != read_char(reader)) {
				Msg.info(this, "bad S");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_D != read_char(reader)) {
				Msg.info(this, "bad D");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-3, 0x10);
				throw new IOException();
			}
		}
	}

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
		private final String NAME = "ASW";
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
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "Bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_W != read_char(reader)) {
				Msg.info(this, "Bad W");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
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

	/*
	 * Starting Address (ASG)
	 *
	 * {$E2}{$C7}{$BE}{n1}{$BF}
	 */
	public class MufomASG extends MufomRecord {
		private final String NAME = "ASG";
		public long starting_address = -1;

		private void print() {
			String msg = NAME + ": " + Long.toHexString(starting_address);
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

		public MufomASG(BinaryReader reader) throws IOException {
			Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
			if (MufomType.MUFOM_CMD_AS != read_char(reader)) {
				Msg.info(this, "bad AS");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_G != read_char(reader)) {
				Msg.info(this, "bad G");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}

			if (MufomType.MUFOM_OPEN != read_char(reader)) {
				Msg.info(null, "Expecting MUFOM_OPEN");
				throw new IOException();
			}

			starting_address = read_int(reader);

			if (MufomType.MUFOM_CLOSE != read_char(reader)) {
				Msg.info(null, "Expecting MUFOM_CLOSE");
				throw new IOException();
			}
			print();
		}
	}

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
		private final String NAME = "ATN";
		public long symbol_name_index = -1;
		public long attribute_definition = -1;
        private String id = null;
        private long x1 = -1;
        private long x2 = -1;
        private long x3 = -1;
        private long x4 = -1;
        private long x5 = -1;
        private long x6 = -1;
        private boolean has_asn = false;

        private void print() {
			String msg = NAME + ": " + symbol_name_index + " " + attribute_definition;
			if (do_debug) {
				Msg.info(this, msg);
			} else {
				Msg.trace(this, msg);
			}
		}

        public MufomATN(BinaryReader reader, boolean must) throws IOException {
        	Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER " + NAME);
        	if (!must && omit_cmd(reader)) {
				return;
			}
        	if (MufomType.MUFOM_CMD_AT != read_char(reader)) {
				Msg.info(this, "Bad AT");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (MufomType.MUFOM_ID_N != read_char(reader)) {
				Msg.info(this, "Bad N");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-2, 0x10);
				throw new IOException();
			}
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
            case MufomType.ieee_static_variable_enum:
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

	/*
	 * Module End (ASW7)
	 *
	 * Module End (ME) - $E1
	 */
	public class MufomEnd {
		private final int asw_index = 7;
		public MufomME me = null;

		private void valid() throws IOException {
			if (reader.getPointerIndex() != reader.length()) {
				//TODO trailing data?
			}
		}

		public MufomEnd() throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomEnd");
			me = new MufomME(reader);
			valid();
		}
	}

	/*
	 * Trailer Part (ASW6)
	 *
	 * Execution Starting Address (ASG) - $E2C7
	 */
	public class MufomTrailer {
		private final int asw_index = 6;
		public MufomTrailer next = null;
		public MufomASG asg = null;

		private void valid() throws IOException {

		}

		public MufomTrailer() throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomTrailer");
			asg = new MufomASG(reader);
			valid();
		}
	}

	/*
	 * Data Part (ASW5)
	 *
	 * Current Section (SB) - $E5
	 * Current Section PC (ASP) - $E2D0
	 * Load Constant MAUs (LD) - $ED
	 * Repeat Data (RE) - $F7
	 */
	public class MufomData {
		private final int asw_index = 5;
		public MufomData next = null;
		public MufomSB sb = null;
		public MufomASP asp = null;
		public MufomLD ld = null;
		public MufomRE re = null;

		private void valid() throws IOException {
		}

		public long getDataOffset() {
			return ld.data_bytes_offset;
		}

		public long getDataLength() {
			return ld.address_units;
		}

		public long getSectionNumber() {
			if (null != sb) {
				return sb.section_number;
			}
			return 0;
		}

		public long getSectionAddress() {
			if (null == asp) {
				// How do you get the section address when ASP is not defined
				long section_number = getSectionNumber();
				MufomSectionDefinition tmp = asw2;
				while (null != tmp) {
					if (section_number == tmp.getSectionIndex()) {
						return tmp.getBaseAddress();
					}
					tmp = tmp.next;
				}

				return -1;
			}
			return asp.current_pc;
		}

		public MufomData(MufomData x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomData");
			if (MufomSB.check(reader)) {
				sb = new MufomSB(reader);
			} else {
				// no SB is defined, the current section is 0
			}
			if (MufomASP.check(reader)) {
				asp = new MufomASP(reader);
			} else {
				// no ASP is defined, the PC is the start of the section
			}
			ld = new MufomLD(reader);
			//re = new MufomRE(reader);
			valid();
			if (null != x) {
				x.next = this;
			}
		}
	}

	/*
	 * Debug Information Part (ASW4)
	 *
	 * Declare Block Beginning (BB) - $F8
	 * Declare Type Name, filename, line numbers, function name, variable names, etc. (NN) - $F0
	 * Define Type Characteristics (TY) - $F2
	 * Variable Attributes (ATN) - $F1CE
	 * Variable Values (ASN) - $E2CE
	 * Declare Block End (BE) - $F9
	 */
	public class MufomDebugInformation {
		private final int asw_index = 4;
		public MufomDebugInformation next = null;
		public MufomBB bb = null;
		public MufomNN nn = null;
		public MufomTY ty = null;
		public MufomATN atn = null;
		public MufomASN asn = null;
		public MufomCompiler id = null;
		public MufomBE be = null;

		private void valid() throws IOException {

		}

		public MufomDebugInformation(MufomDebugInformation x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomDebugInformation");
			bb = new MufomBB(reader);
			nn = new MufomNN(reader, false);
			ty = new MufomTY(reader, false);
			atn = new MufomATN(reader, false);
			asn = new MufomASN(reader, false);
			id = new MufomCompiler(reader, false);
			be = new MufomBE(reader, (int) bb.begin_block);
			valid();
			if (null != x) {
				x.next = this;
			}
		}
	}

	/*
	 * External Part (ASW3)
	 *
	 * Public (External) Symbol (NI) - $E8
	 * Variable Attribute (ATI) - $F1C9
	 * Variable Values (ASI) - $E2C9
	 */
	public class MufomExternal {
		private final int asw_index = 3;
		public MufomExternal next = null;
		public MufomNI ni = null;
		public MufomATI ati = null;
		public MufomASI asi = null;

		private void valid() throws IOException {
			if (ni.symbol_name_index != ati.symbol_name_index ||
					ni.symbol_name_index != asi.symbol_name_index) {
				Msg.info(this, "Bad symbol index");
				throw new IOException();
			}
		}

		public String getName() {
			return ni.symbol_name;
		}

		public long getIndex() {
			return ni.symbol_name_index;
		}

		public long getAddress() {
			return asi.symbol_value;
		}

		public DataType getType() {
			return null;
		}

		public MufomExternal(MufomExternal x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomExternal");
			ni = new MufomNI(reader);
			ati = new MufomATI(reader);
			asi = new MufomASI(reader);
			valid();
			if (null != x) {
				x.next = this;
			}
		}
	}

	/*
	 * Section Definition Part (ASW2)
	 *
	 * Section Type (ST) - $E6
	 * Section Size (ASS) - $E2D3
	 * Section Base Address (ASL) - $E2CC
	 */
	public class MufomSectionDefinition {
		private final int asw_index = 2;
		public MufomSectionDefinition next = null;
		public MufomST st = null;
		public MufomSA sa = null;
		private MufomASS ass = null;
		private MufomASL asl = null;

		private void valid() throws IOException {
			if (st.section_number != ass.section_number ||
					st.section_number != asl.section_number ||
					st.section_number != sa.section_number) {
				Msg.info(this, "Bad section index");
				throw new IOException();
			}
		}

		public long getSectionIndex() {
			return st.section_number;
		}

		public long getSectionLength() {
			return ass.section_size;
		}

		public long getBaseAddress() {
			return asl.section_base_address;
		}

		public String getName() {
			return st.section_name;
		}

		public MufomSectionDefinition(MufomSectionDefinition x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomSectionDefinition");
			st = new MufomST(reader);
			sa = new MufomSA(reader);
			ass = new MufomASS(reader);
			asl = new MufomASL(reader);
			valid();
			if (null != x) {
				x.next = this;
			}
		}
	}

	/*
	 * Environment Part (ASW1)
	 *
	 * Variable Attributes (NN) - $F0
	 * Variable Attributes (ATN) - $F1CE
	 * Variable Values (ASN) - $E2CE
	 */
	public class MufomEnvironment {
		private final int asw_index = 1;
		public MufomEnvironment next = null;
		public MufomNN nn = null;
		public MufomATN atn = null;
		public MufomASN asn = null;

		private void valid() throws IOException {
			if (nn.symbol_name_index != atn.symbol_name_index) {
				Msg.info(this, "Bad symbol_name_index");
				throw new IOException();
			}
		}

		public MufomEnvironment(MufomEnvironment x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomEnvironment");
			if (null == x) {
				nn = new MufomNN(reader, true);
			} else {
				x.next = this;
				nn = x.nn;
			}
			atn = new MufomATN(reader, true);
			if (atn.has_asn) {
				asn = new MufomASN(reader, true);
			}
			valid();
		}
	}

	/*
	 * AD Extension Part (ASW0)
	 *
	 * Variable Attributes (NN) - $F0
	 * Variable Attributes (ATN) - $F1CE
	 * Variable Values (ASN) - $E2CE
	 */
	public class MufomADExtension {
		private final int asw_index = 0;
		public MufomADExtension next = null;
		public MufomNN nn = null;
		public MufomATN atn = null;
		public MufomASN asn = null;

		private void valid() throws IOException {
			if (nn.symbol_name_index != atn.symbol_name_index) {
				Msg.info(this, "Bad symbol_name_index");
				throw new IOException();
			}
		}

		public MufomADExtension(MufomADExtension x) throws IOException {
			Msg.trace(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomADExtension");
			if (null == x) {
				nn = new MufomNN(reader, true);
			} else {
				x.next = this;
				nn = x.nn;
			}
			atn = new MufomATN(reader, true);
			if (atn.has_asn) {
				asn = new MufomASN(reader, true);
			}
			valid();
		}
	}

	/*
	 * Module Beginning (MB) - $E0
	 * Address Descriptor (AD) - $EC
	 * Assign Value to Variable W0 (ASW0) - $E2D700
	 * Assign Value to Variable WI (ASW1) - $E2D701
	 * Assign Value to Variable W2 (ASW2) - $E2D702
	 * Assign Value to Variable W3 (ASW3) - $E2D703
	 * Assign Value to Variable W4 (ASW4) - $E2D704
	 * Assign Value to Variable W5 (ASW5) - $E2D705
	 * Assign Value to Variable W6 (ASW6) - $E2D706
	 * Assign Value to Variable W7 (ASW7) - $E2D707
	 */
	public class MufomHeaderPart {
		public MufomMB mb = null;
		public MufomAD ad = null;
		public long[] asw_offset = {-1, -1, -1, -1, -1, -1, -1, -1};
		public long[] asw_end = {-1, -1, -1, -1, -1, -1, -1, -1};

		public MufomHeaderPart() throws IOException {
			Msg.trace(this, String.format("%08x-%08x ", 0, reader.length()) + "PARSE MufomHeaderPart");
			mb = new MufomMB(reader);
			ad = new MufomAD(reader);

			for (int i = 0; i < 8; i++) {
				MufomASW tmp = new MufomASW(reader);
				asw_offset[(int) tmp.asw_index] = tmp.asw_offset;
			}
			for (int i = 0; i < 8; i++) {
				if (asw_offset[i] == 0) {
					asw_end[i] = 0;
					continue;
				}
				for (int j = 0; j < 8; j ++) {
					if (asw_offset[i] >= asw_offset[j]) {
						continue;
					}
					if (asw_end[i] == -1) {
						asw_end[i] = asw_offset[j];
					} else if (asw_end[i] > asw_offset[j]) {
						asw_end[i] = asw_offset[j];
					}
				}
				if (-1 == asw_end[i]) {
					asw_end[i] = reader.length();
				}
			}
		}
	}
}
