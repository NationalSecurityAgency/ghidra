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
import ghidra.util.Msg;
import resources.ResourceManager;

public class AIFFDataType extends BuiltIn implements Dynamic {

	//first four bytes must = FORM then skip four then next four must = AIFF
	public static byte[] MAGIC =
		new byte[] { (byte) 'F', (byte) 'O', (byte) 'R', (byte) 'M', (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 'A', (byte) 'I', (byte) 'F', (byte) 'F' };
	public static byte[] MAGIC_MASK =
		new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

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
			if (!checkMagic(buf)) {
				return -1;
			}

			return (buf.getInt(4) + 8);
		}
		catch (Exception e) {
			Msg.debug(this, "Invalid AIFF data at " + buf.getAddress());
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

	private static class AIFFData implements Playable {

		private static final ImageIcon AUDIO_ICON =
			ResourceManager.loadImage("images/audio-volume-medium.png");
		private byte[] bytes;

		public AIFFData(byte[] bytes) {
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
			Msg.error(this, "AIFF-Sound error: Not enough bytes in memory");
			return null;
		}
		return new AIFFData(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return AIFFData.class;
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
