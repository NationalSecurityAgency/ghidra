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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

public class PngDataType extends BuiltIn implements Dynamic, Resource {
	public static byte[] MAGIC = new byte[] { (byte) 0x89, (byte) 0x50, (byte) 0x4e, (byte) 0x47,
		(byte) 0x0d, (byte) 0x0a, (byte) 0x1a, (byte) 0x0a };

	public static byte[] MASK = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public PngDataType() {
		this(null);
	}

	public PngDataType(DataTypeManager dtm) {
		super(null, "PNG-Image", dtm);
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		try {
			PngResource png = new PngResource(buf);
			return png.getLength();
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "PNG error: " + e.getMessage());
		}
		catch (InvalidDataTypeException e) {
			Msg.error(this, "Invalid PNG data at " + buf.getAddress());
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
		return new PngDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "PNG Image stored within program";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "PNG";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<PNG-Image>";
	}

	private static class PngDataImage extends DataImage {

		private final byte[] data;

		PngDataImage(byte[] data) {
			this.data = data;
		}

		@Override
		public ImageIcon getImageIcon() {
			return new ImageIcon(data, "<PNG-Image>");
		}

		@Override
		public String getImageFileType() {
			return "png";
		}
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			return null;
		}
		return new PngDataImage(data);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return PngDataImage.class;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "PNG";
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}
}
