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

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

/**
 * AIFF / AIFC header format:
 * <pre>
 * struct {
 * 	int32 ckID;				'FORM'
 * 	int32 ckDataSize;
 * 	int32 formType;			'AIFF', 'AIFC'
 *  -variable length chunk data-
 * }
 * </pre> 
 *
 */
public class AIFFDataType extends BuiltIn implements Dynamic {

	/**
	 * Magic bytes for 'AIFF' audio file header
	 */
	public static byte[] MAGIC_AIFF =
		new byte[] {
			(byte) 'F', (byte) 'O', (byte) 'R', (byte) 'M',
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 'A', (byte) 'I', (byte) 'F', (byte) 'F' };
	/**
	 * Magic bytes for 'AIFC' audio file header (almost same as AIFF)
	 */
	public static byte[] MAGIC_AIFC =
		new byte[] {
			(byte) 'F', (byte) 'O', (byte) 'R', (byte) 'M',
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 'A', (byte) 'I', (byte) 'F', (byte) 'C' };

	/**
	 * Byte search mask for magic bytes
	 */
	public static byte[] MAGIC_MASK =
		new byte[] {
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public AIFFDataType() {
		this(null);
	}

	public AIFFDataType(DataTypeManager dtm) {
		super(null, "AIFF-Sound", dtm);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		try {
			if (!checkMagic(buf, MAGIC_AIFF) && !checkMagic(buf, MAGIC_AIFC)) {
				return -1;
			}

			int dataSize = buf.getInt(4);
			if (dataSize <= 0) {
				// check dataSize for validity.  TODO: more strict with upper bounds
				return -1;
			}

			return dataSize + 8;
		}
		catch (Exception e) {
			Msg.debug(this, "Invalid AIFF data at " + buf.getAddress());
		}
		return -1;
	}

	private boolean checkMagic(MemBuffer buf, byte[] magicBytes) throws MemoryAccessException {
		for (int i = 0; i < magicBytes.length; i++) {
			if (magicBytes[i] != (buf.getByte(i) & MAGIC_MASK[i])) {
				return false;
			}
		}

		return true;
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
		return new AIFFDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "AIFF sound stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "AIFF";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<AIFF-Representation>";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			Msg.error(this, "AIFF-Sound error: Not enough bytes in memory");
			return null;
		}
		return new AudioPlayer(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return AudioPlayer.class;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return "AIFF";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
