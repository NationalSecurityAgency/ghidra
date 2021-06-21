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

import java.awt.image.BufferedImage;
import java.nio.ByteOrder;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

public class JPEGDataType extends BuiltIn implements Dynamic, Resource {
	public static byte[] MAGIC = new byte[] { (byte) 0xff, (byte) 0xd8, (byte) 0, (byte) 0,
		(byte) 0, (byte) 0, (byte) 'J', (byte) 'F', (byte) 'I', (byte) 'F', (byte) 0 };

	public static byte[] MAGIC_MASK = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0, (byte) 0,
		(byte) 0, (byte) 0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public JPEGDataType() {
		this(null);
	}

	public JPEGDataType(DataTypeManager dtm) {
		super(null, "JPEG-Image", dtm);
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
			MemBufferImageInputStream inputStream =
				new MemBufferImageInputStream(buf, ByteOrder.BIG_ENDIAN);
			BufferedImage image = ImageIO.read(inputStream);
			if (image != null) {
				int length = inputStream.getConsumedLength();
				return length;
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Invalid JPEG data at " + buf.getAddress());
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
		return new JPEGDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "JPEG Image stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "JPG";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<JPEG-Image>";
	}

	private static class JPEGDataImage extends DataImage {

		private final byte[] data;

		JPEGDataImage(byte[] data) {
			this.data = data;
		}

		@Override
		public ImageIcon getImageIcon() {
			return new ImageIcon(data, "<JPEG-Image>");
		}

		@Override
		public String getImageFileType() {
			return "jpg";
		}
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			return null;
		}
		return new JPEGDataImage(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return JPEGDataImage.class;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return "JPEG";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
