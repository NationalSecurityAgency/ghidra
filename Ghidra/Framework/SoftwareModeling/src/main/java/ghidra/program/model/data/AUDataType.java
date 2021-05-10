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

import java.awt.event.MouseEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.sound.sampled.*;
import javax.swing.ImageIcon;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.GhidraBigEndianDataConverter;
import ghidra.util.Msg;
import resources.ResourceManager;

public class AUDataType extends BuiltIn implements Dynamic {
	public static byte[] MAGIC = new byte[] { (byte) '.', (byte) 's', (byte) 'n', (byte) 'd' };

	public static byte[] MAGIC_MASK =
		new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public AUDataType() {
		this(null);
	}

	public AUDataType(DataTypeManager dtm) {
		super(null, "AU-Sound", dtm);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {

		try {
			if (!checkMagic(buf)) {
				Msg.debug(this, "Invalid AU magic number");
				return -1;
			}
			//Ints always stored as big endian in this format but can be in any kind of program so must get the ints as big endian even when in a little endian program			
			int dataOffset = GhidraBigEndianDataConverter.INSTANCE.getInt(buf, 4);

			int dataSize = GhidraBigEndianDataConverter.INSTANCE.getInt(buf, 8);

			int totalSize = dataOffset + dataSize; //header + data = total size			
			return totalSize;

		}
		catch (Exception e) {
			Msg.debug(this, "Invalid AU data at " + buf.getAddress());
		}
		return -1;
	}

	private boolean checkMagic(MemBuffer buf) throws MemoryAccessException {
		for (int i = 0; i < MAGIC.length; i++) {
			if (MAGIC[i] != (buf.getByte(i) & MAGIC_MASK[i])) {
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
		return new AUDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "AU sound stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "AU";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<AU-Representation>";
	}

	private static class AUData implements Playable {

		private static final ImageIcon AUDIO_ICON =
			ResourceManager.loadImage("images/audio-volume-medium.png");
		private byte[] bytes;

		public AUData(byte[] bytes) {
			this.bytes = bytes;
		}

		@Override
		public void clicked(MouseEvent event) {

			try {
				Clip clip = AudioSystem.getClip();
				AudioInputStream ais =
					AudioSystem.getAudioInputStream(new ByteArrayInputStream(bytes));
				clip.open(ais);
				clip.start();
			}
			catch (UnsupportedAudioFileException | IOException | LineUnavailableException e) {
				Msg.debug(this, "Unable to play audio", e);
			}
		}

		@Override
		public ImageIcon getImageIcon() {
			return AUDIO_ICON;
		}
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			Msg.error(this, "AU-DataTpe Error: Not enough bytes in memory");
			return null;
		}
		return new AUData(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return AUData.class;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return "AU";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
