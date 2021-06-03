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

import javax.swing.ImageIcon;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;

public class GifDataType extends BuiltIn implements Dynamic, Resource {
	public static byte[] MAGIC_87 =
		new byte[] { (byte) 'G', (byte) 'I', (byte) 'F', (byte) '8', (byte) '7', (byte) 'a' };
	public static byte[] MAGIC_89 =
		new byte[] { (byte) 'G', (byte) 'I', (byte) 'F', (byte) '8', (byte) '9', (byte) 'a' };
	public static byte[] GIFMASK =
		new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public GifDataType() {
		this(null);
	}

	public GifDataType(DataTypeManager dtm) {
		super(null, "GIF-Image", dtm);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		try {
			try {
				GIFResource gif = new GIFResource(buf);
				return gif.getLength();
			}
			catch (InvalidDataTypeException e) {
				Msg.error(this, "Invalid GIF data at " + buf.getAddress());
			}
			return -1;

		}
		catch (Exception e) {
			Msg.error(this, "Invalid GIF data at " + buf.getAddress());
		}
		return -1;
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
		return new GifDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "GIF Image stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "GIF";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<GIF-Image>";
	}

	private static class GifDataImage extends DataImage {

		private final byte[] data;

		GifDataImage(byte[] data) {
			this.data = data;
		}

		@Override
		public ImageIcon getImageIcon() {
			return new ImageIcon(data, "<GIF-Image>");
		}

		@Override
		public String getImageFileType() {
			return "gif";
		}
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			return null;
		}
		return new GifDataImage(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return GifDataImage.class;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "GIF";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}
}
