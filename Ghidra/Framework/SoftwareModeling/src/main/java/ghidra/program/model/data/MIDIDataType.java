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
package ghidra.program.model.data;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;

public class MIDIDataType extends BuiltIn implements Dynamic {
	public MIDIDataType() {
		this(null);
	}

	public MIDIDataType(DataTypeManager dtm) {
		super(null, "MIDI-Score", dtm);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		try {
			return computeLength(buf, maxLength);
		}
		catch (Exception e) {
			Msg.debug(this, "Invalid MIDI data at " + buf.getAddress());
		}
		return -1;
	}

	private long readUnsignedInteger(InputStream stream) throws IOException {
		long value = 0;
		for (int index = 0; index < 4; index++) {
			int currentByte = stream.read();
			if (currentByte == -1) {
				throw new EOFException();
			}
			value = (value << 8) | currentByte;
		}
		return value;
	}
	
	private int readUnsignedShort(InputStream stream) throws IOException {
		int value = 0;
		for (int index = 0; index < 2; index++) {
			int currentByte = stream.read();
			if (currentByte == -1) {
				throw new EOFException();
			}
			value = (value << 8) | currentByte;
		}
		return value;
	}
	
	private int computeLength(MemBuffer buf, int maxLength) throws IOException, InvalidDataTypeException {
		int computedLength = -1;
		
		try (InputStream stream = buf.getInputStream(0, maxLength > 0 ? maxLength : Integer.MAX_VALUE)) {
			byte[] chunkType = new byte[4];
			if (stream.read(chunkType) < chunkType.length) {
				throw new EOFException();
			}
			if (chunkType[0] != (byte)'M' ||
				chunkType[1] != (byte)'T' ||
				chunkType[2] != (byte)'h' ||
				chunkType[3] != (byte)'d') {
				return -1;
			}
			long chunkLength = readUnsignedInteger(stream);
			if (chunkLength != 6) {
				throw new InvalidDataTypeException("Unexpected header length.");
			}
			stream.skip(2);
			int tracks = readUnsignedShort(stream);
			stream.skip(2);
			computedLength = 14;
			while (tracks > 0) {
				if (stream.read(chunkType) < chunkType.length) {
					throw new EOFException();
				}
				chunkLength = readUnsignedInteger(stream);
				stream.skip(chunkLength);
				computedLength += 8 + chunkLength;
				if (chunkType[0] != (byte)'M' ||
					chunkType[1] != (byte)'T' ||
					chunkType[2] != (byte)'r' ||
					chunkType[3] != (byte)'k') {
					continue;
				}
				tracks--;
			}
		} finally {
		}
		
		return computedLength;
	}
	
	@Override
	public boolean canSpecifyLength() {
		return false;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MIDIDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "MIDI score stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "MIDI";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<MIDI-Resource>";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			Msg.error(this, "MIDI-Score error: Not enough bytes!");
			return null;
		}
		return new ScorePlayer(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return ScorePlayer.class;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return "MIDI";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
