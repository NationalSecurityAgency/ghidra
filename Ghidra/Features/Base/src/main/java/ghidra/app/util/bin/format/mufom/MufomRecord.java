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
				throw new IOException();
			}
			return -1;
		}
	}

	protected void hexdump(BinaryReader reader, long position, long length) throws IOException {
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
				throw new IOException();
			}
			return null;
		}
		long offset = reader.getPointerIndex();
		if (offset + len > reader.length()) {
			Msg.info(null, "Bad pascal string "+ len +" + " + offset + " > " + reader.length());
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
}
