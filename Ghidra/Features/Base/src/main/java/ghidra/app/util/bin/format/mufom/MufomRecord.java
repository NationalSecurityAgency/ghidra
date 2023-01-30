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

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public abstract class MufomRecord {
	public static boolean do_debug = true;
	public static long record_offset = -1;

	protected long read_integer(BinaryReader reader, boolean must) throws IOException {
		long offset = reader.getPointerIndex();
		long result = reader.readUnsignedByte(offset);
		if (result <= 0x7f) {
			reader.readNextUnsignedByte();
			return result;
		} else if (result >= 0x80 && result <= 0x88) {
			long size = result - 0x80;
			reader.readNextUnsignedByte();
			result = 0;
			for (long i = 0; i < size; i++) {
				result = (result << 8) | reader.readNextUnsignedByte();
			}
			return result;
		} else {
			if (must) {
				Msg.info(null, "Failed to parse int " + result);
				if (do_debug) hexdump(reader, record_offset, 0x10);
				throw new IOException();
			}
			return -1;
		}
	}

	public static void hexdump(BinaryReader reader, long position, long length) throws IOException {
		long current = reader.getPointerIndex();
		if (position > 0) {
			reader.setPointerIndex(position);
		}
		long start = reader.getPointerIndex();

		if (start + length > reader.length()) {
			length = reader.length() - start;
		}

		String x = " " + Long.toHexString(position) + " " + length + " " +
				Long.toHexString(current) + " 0x" + Long.toHexString(start) + "\n";
		for (long i = 0; i < length; i++) {
			x = x + " 0x" + Long.toHexString(0xff & reader.readUnsignedByte(start + i));
			if (((i + 1) % 16) == 0) x = x + '\n';
		}
		x = x + '\n';
		reader.setPointerIndex(start);
		for (long i = 0; i < length; i++) {
			int val = reader.readUnsignedByte(start + i);
			if (val > 127 || val < 32) val = '.';
			x = x + " " + (char)val;
			if (((i + 1) % 16) == 0) x = x + '\n';
		}
		Msg.info(null, x);
		reader.setPointerIndex(current);
	}

	protected String read_string(BinaryReader reader, boolean must) throws IOException {
		int len = reader.readUnsignedByte(reader.getPointerIndex());
		if (0x7f >= len) {
			reader.readNextUnsignedByte();
		} else if (MufomType.MUFOM_EXTB == len) {
			reader.readNextUnsignedByte();
			len = reader.readNextUnsignedByte();
		} else if (MufomType.MUFOM_EXTH == len) {
			reader.readNextUnsignedByte();
			len = reader.readNextUnsignedShort();
		} else {
			if (must) {
				Msg.info(this, "Failed to read string");
				if (do_debug) hexdump(reader, record_offset, 0x10);
				throw new IOException();
			}
			return null;
		}
		long offset = reader.getPointerIndex();
		if (offset + len > reader.length()) {
			Msg.info(null, "Bad pascal string "+ len +" + " + offset + " > " + reader.length());
			if (do_debug) hexdump(reader, record_offset, 0x10);
			throw new IOException();
		}
		String x = new String(reader.readNextByteArray(len));
		return x;
	}

	protected String read_id(BinaryReader reader) throws IOException {
		return read_string(reader, true);
	}

	protected String read_opt_id(BinaryReader reader) throws IOException {
		return read_string(reader, false);
	}

	protected long read_int(BinaryReader reader) throws IOException {
		return read_integer(reader, true);
	}

	protected long read_opt_int(BinaryReader reader) throws IOException {
		return read_integer(reader, false);
	}

	protected int read_letter(BinaryReader reader, boolean must) throws IOException {
		int letter = reader.readUnsignedByte(reader.getPointerIndex());

		//TODO
//		if (MufomType.MUFOM_ID_A > letter || letter > MufomType.MUFOM_ID_Z) {
//			if (must) {
//				Msg.info(this, "Bad letter");
//				throw new IOException();
//			} else {
//				return -1;
//			}
//		}

		reader.readNextUnsignedByte();
		return letter;
	}

	protected int read_char(BinaryReader reader) throws IOException {
		return read_letter(reader, true);
	}

	protected int read_opt_char(BinaryReader reader) throws IOException {
		return read_letter(reader, false);
	}

	protected boolean omit_cmd(BinaryReader reader) throws IOException {
		int tmp = reader.readUnsignedByte(reader.getPointerIndex());
		if (MufomType.MUFOM_OMITTED == tmp) {
			reader.readNextUnsignedByte();
			return true;
		}
		return false;
	}
	
	protected void read_record_type(BinaryReader reader, int record_type, int record_subtype, String name)
			throws IOException {
		int tmp_type = -1;

		Msg.warn(this, String.format("%08x ENTER %s", reader.getPointerIndex(), name));
		tmp_type = read_char(reader);
		if (record_type != tmp_type) {
			Msg.info(this, String.format("Bad type %u != %u, %s", tmp_type, record_type, name));
			if (do_debug) hexdump(reader, record_offset, 0x10);
			throw new IOException();
		}
		if (-1 != record_subtype) {
			int tmp_subtype = read_char(reader);
			if (record_subtype != tmp_subtype) {
				Msg.info(this, String.format("Bad subtype %u != %u, %s", tmp_subtype, record_subtype, name));
				if (do_debug) hexdump(reader, record_offset, 0x10);
				throw new IOException();
			}
		}
	}
	
	public static MufomRecord readRecord(BinaryReader reader) throws IOException {
		record_offset = reader.getPointerIndex();
		int record_type = reader.readUnsignedByte(record_offset);
		int record_subtype = -1;

		switch (record_type) {
		case MufomType.MUFOM_OMITTED:
			reader.readNextUnsignedByte();
			return null;
		case MufomType.MUFOM_CMD_MB:
			return new MufomMB(reader);
		case MufomType.MUFOM_CMD_ME:
			return new MufomME(reader);
		case MufomType.MUFOM_CMD_AS:
			record_subtype = reader.readUnsignedByte(record_offset + 1);
			switch (record_subtype) {
			case MufomType.MUFOM_ID_G:
				return new MufomASG(reader);
			case MufomType.MUFOM_ID_I:
				return new MufomASI(reader);
			case MufomType.MUFOM_ID_L:
				return new MufomASL(reader);
			case MufomType.MUFOM_ID_N:
				return new MufomASN(reader);
			case MufomType.MUFOM_ID_P:
				return new MufomASP(reader);
			case MufomType.MUFOM_ID_R:
				return new MufomASR(reader);
			case MufomType.MUFOM_ID_S:
				return new MufomASS(reader);
			case MufomType.MUFOM_ID_W:
				return new MufomASW(reader);
			case MufomType.MUFOM_ID_X:
				return new MufomASX(reader);
			case MufomType.MUFOM_ID_F:
				return new MufomASF(reader);
			default:
				if (do_debug) hexdump(reader, record_offset, 0x10);
				throw new IOException();
			}
		case MufomType.MUFOM_CMD_IR:
			return new MufomIR(reader);
		case MufomType.MUFOM_CMD_LR:
			return new MufomLR(reader);
		case MufomType.MUFOM_CMD_SB:
			return new MufomSB(reader);
		case MufomType.MUFOM_CMD_ST:
			return new MufomST(reader);
		case MufomType.MUFOM_CMD_SA:
			return new MufomSA(reader);
		case MufomType.MUFOM_CMD_NI:
			return new MufomNI(reader);
		case MufomType.MUFOM_CMD_NX:
			return new MufomNX(reader);
		case MufomType.MUFOM_CMD_CO:
			return new MufomCO(reader);
		case MufomType.MUFOM_CMD_DT:
			return new MufomDT(reader);
		case MufomType.MUFOM_CMD_AD:
			return new MufomAD(reader);
		case MufomType.MUFOM_CMD_LD:
			return new MufomLD(reader);
		case MufomType.MUFOM_CMD_CSS:
			return new MufomCSS(reader);
		case MufomType.MUFOM_CMD_CS:
			return new MufomCS(reader);
		case MufomType.MUFOM_CMD_NN:
			return new MufomNN(reader);
		case MufomType.MUFOM_CMD_AT:
			record_subtype = reader.readUnsignedByte(record_offset + 1);
			switch (record_subtype) {
			case MufomType.MUFOM_ID_I:
				return new MufomATI(reader);
			case MufomType.MUFOM_ID_N:
				return new MufomATN(reader);
			case MufomType.MUFOM_ID_X:
				return new MufomATX(reader);
			default:
				if (do_debug) hexdump(reader, record_offset, 0x10);
				throw new IOException();
			}
		case MufomType.MUFOM_CMD_TY:
			return new MufomTY(reader);
		case MufomType.MUFOM_CMD_RI:
			return new MufomRI(reader);
		case MufomType.MUFOM_CMD_WX:
			return new MufomWX(reader);
		case MufomType.MUFOM_CMD_LI:
			return new MufomLI(reader);
		case MufomType.MUFOM_CMD_LX:
			return new MufomLX(reader);
		case MufomType.MUFOM_CMD_RE:
			return new MufomRE(reader);
		case MufomType.MUFOM_CMD_SC:
			return new MufomBB(reader);
		case MufomType.MUFOM_CMD_LN:
			return new MufomLN(reader);
		default:
			if (do_debug) hexdump(reader, record_offset, 0x10);
			throw new IOException();
		}
	}
}
