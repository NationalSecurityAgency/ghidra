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
		Msg.warn(this, String.format("%08x-%08x ", 0, reader.length()) + "PARSE MUFOM");
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
				Msg.warn(this, msg);
			}
		}

		public MufomCompiler(BinaryReader reader) throws IOException {
			Msg.warn(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomCompiler");
			nn = new MufomNN(reader);
			atn = new MufomATN(reader);
			asntool = new MufomASN(reader);
			asntype = new MufomASN(reader);
			asnsize = new MufomASN(reader);
			atn1 = new MufomATN(reader);
			asnyear = new MufomASN(reader);
			asnmonth = new MufomASN(reader);
			asnday = new MufomASN(reader);
			asnhour = new MufomASN(reader);
			asnminute = new MufomASN(reader);
			asnsecond = new MufomASN(reader);
			print();
		}
	}



	/*
	 * Absolute Code
	 *
	 * {$C1}{$D3}{$D0}
	 */
	public class MufomAbsCode extends MufomRecord {
		public static final String NAME = "CODE";
		public static final int record_type = MufomType.MUFOM_ID_A;
		public static final int record_subtype = MufomType.MUFOM_ID_S ;

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (record_type == reader.readUnsignedByte(offset + 0) &&
					record_subtype == reader.readUnsignedByte(offset + 1) &&
							MufomType.MUFOM_ID_P == reader.readUnsignedByte(offset + 2)) {
				return true;
			}
			return false;
		}

		public MufomAbsCode(BinaryReader reader) throws IOException {
			Msg.warn(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomAbsCode");
			if (record_type != read_char(reader)) {
				Msg.info(this, "bad A");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (record_subtype != read_char(reader)) {
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
		public static final String NAME = "DATA";
		public static final int record_type = MufomType.MUFOM_ID_A;
		public static final int record_subtype = MufomType.MUFOM_ID_S;

		public static boolean check(BinaryReader reader) throws IOException {
			long offset = reader.getPointerIndex();
			if (record_type == reader.readUnsignedByte(offset + 0) &&
					record_subtype == reader.readUnsignedByte(offset + 1) &&
							MufomType.MUFOM_ID_D == reader.readUnsignedByte(offset + 2)) {
				return true;
			}
			return false;
		}

		public MufomAbsData(BinaryReader reader) throws IOException {
			Msg.warn(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomAbsData");
			if (record_type != read_char(reader)) {
				Msg.info(this, "bad A");
				if (do_debug) hexdump(reader, reader.getPointerIndex()-1, 0x10);
				throw new IOException();
			}
			if (record_subtype != read_char(reader)) {
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
	 * Module End (ASW7)
	 *
	 * Module End (ME) - $E1
	 */
	public class MufomEnd {
		private final int asw_index = MufomType.MUFOM_ASW7;
		public MufomME me = null;

		private void valid() throws IOException {
			if (reader.getPointerIndex() != reader.length()) {
				//TODO trailing data?
			}
		}

		public MufomEnd() throws IOException {
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomEnd");
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomME) {
				me = (MufomME) record;
			}
			valid();
		}
	}

	/*
	 * Trailer Part (ASW6)
	 *
	 * Execution Starting Address (ASG) - $E2C7
	 */
	public class MufomTrailer {
		private final int asw_index = MufomType.MUFOM_ASW6;
		public MufomTrailer next = null;
		public MufomASG asg = null;

		private void valid() throws IOException {

		}

		public MufomTrailer() throws IOException {
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomTrailer");
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomASG) {
				asg = (MufomASG) record;
			}
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
		private final int asw_index = MufomType.MUFOM_ASW5;
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
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomData");
			if (null != x) {
				x.next = this;
			}
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomSB) {
				sb = (MufomSB) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASP) {
				asp = (MufomASP) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomLD) {
				ld = (MufomLD) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomRE) {
				re = (MufomRE) record;
			} else {
				reader.setPointerIndex(record.record_offset);
			}
			valid();
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
		private final int asw_index = MufomType.MUFOM_ASW4;
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
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomDebugInformation");
			bb = new MufomBB(reader);
			nn = new MufomNN(reader);
			ty = new MufomTY(reader);
			atn = new MufomATN(reader);
			asn = new MufomASN(reader);
			id = new MufomCompiler(reader);
			be = new MufomBE(reader, (int) bb.begin_block);
			valid();
			if (null != x) {
				x.next = this;
			}
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
		private final int asw_index = MufomType.MUFOM_ASW3;
		public MufomExternal next = null;
		public MufomSB sb = null;
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
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomExternal");
			if (null != x) {
				x.next = this;
			}
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomSB) {
				sb = (MufomSB) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomNI) {
				ni = (MufomNI) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomATI) {
				ati = (MufomATI) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASI) {
				asi = (MufomASI) record;
			} else {
				reader.setPointerIndex(record.record_offset);
			}
			valid();
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
		private final int asw_index = MufomType.MUFOM_ASW2;
		public MufomSectionDefinition next = null;
		public MufomST st = null;
		public MufomSA sa = null;
		private MufomASS ass = null;
		private MufomASL asl = null;

		private void valid() throws IOException {
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
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomSectionDefinition");
			if (null != x) {
				x.next = this;
			}
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomST) {
				st = (MufomST) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomSA) {
				sa = (MufomSA) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASS) {
				ass = (MufomASS) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASL) {
				asl = (MufomASL) record;
			} else {
				reader.setPointerIndex(record.record_offset);
			}
			valid();
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
		private final int asw_index = MufomType.MUFOM_ASW1;
		public MufomEnvironment next = null;
		public MufomNN nn = null;
		public MufomATN atn = null;
		public MufomASN asn = null;

		private void valid() throws IOException {
			if (nn.symbol_name_index != atn.symbol_name_index) {
				Msg.info(this, String.format("Bad symbol_name_index %d != %d",
						nn.symbol_name_index, atn.symbol_name_index));
				throw new IOException();
			}
		}

		public MufomEnvironment(MufomEnvironment x) throws IOException {
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomEnvironment");
			if (null != x) {
				x.next = this;
			}
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			} else {
				nn = x.nn;
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				if (reader.getPointerIndex() >= hdr.asw_end[asw_index]) return;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
			} else {
				reader.setPointerIndex(record.record_offset);
			}
			valid();
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
		private final int asw_index = MufomType.MUFOM_ASW0;
		public MufomADExtension next = null;
		public MufomNN nn = null;
		public MufomATN atn = null;
		public MufomASN asn = null;

		private void valid() throws IOException {
			if (nn.symbol_name_index != atn.symbol_name_index) {
				Msg.info(this, String.format("Bad symbol_name_index %d != %d",
						nn.symbol_name_index, atn.symbol_name_index));
				throw new IOException();
			}
		}

		public MufomADExtension(MufomADExtension x) throws IOException {
			long variable_start = reader.getPointerIndex();
			Msg.warn(this, String.format("%08x - %08x - %08x ", hdr.asw_offset[asw_index], reader.getPointerIndex(),
					hdr.asw_end[asw_index]) + "PARSE MufomADExtension");
			if (null != x) {
				x.next = this;
			}
			MufomRecord record = MufomRecord.readRecord(reader);
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			} else {
				nn = x.nn;
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
			} else {
				reader.setPointerIndex(record.record_offset);
			}
			valid();	
			long variable_end = reader.getPointerIndex();
			if (variable_end == variable_start)
				throw new IOException();
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
			Msg.warn(this, String.format("%08x-%08x ", 0, reader.length()) + "PARSE MufomHeaderPart");
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
