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
import ghidra.util.classfinder.ClassTranslator;

import java.io.IOException;
import java.util.List;

public class IconResourceDataType extends BitmapResourceDataType {

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.IconResourceDataType",
			IconResourceDataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	public IconResourceDataType() {
		this(null, "IconResource", null);
	}

	public IconResourceDataType(DataTypeManager dtm) {
		this(null, "IconResource", dtm);
	}

	protected IconResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "Icon stored as a Resource";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			IconResource icon = new IconResource(buf);
			DataImage img = icon.getDataImage(buf);
			if (img != null) {
				img.setDescription("<Icon-Image>");
			}
			return img;
		}
		catch (IOException ioe) {
			return null;
		}
	}

	@Override
	protected BitmapResource getBitmapResource(MemBuffer buf) {
		try {
			return new IconResource(buf);
		}
		catch (IOException ioe) {
			return null;
		}
	}

	@Override
	protected int addComponents(MemBuffer buf, BitmapResource bmr, List<DataTypeComponent> comps) {
		int offset = super.addComponents(buf, bmr, comps);
		int arraySize = bmr.getMaskLength();
		if (arraySize > 0) {
			Array array = new ArrayDataType(new ByteDataType(), arraySize, 1);
			offset = addComp(array, arraySize, "BitMask", comps, offset);
		}
		return offset;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "IconRes";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<Icon-Image>";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new IconResourceDataType(dtm);
	}
}
