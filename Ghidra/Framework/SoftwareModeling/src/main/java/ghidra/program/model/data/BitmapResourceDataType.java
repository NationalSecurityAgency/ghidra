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
/*
 * Created on Apr 2, 2003
 *
 * To change this generated comment go to 
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.program.model.data;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.classfinder.ClassTranslator;

/**
 * Definition of a Bitmap Resource Data Structure defined within the
 * resources section of a windows executable.
 * 
 * 
 */
public class BitmapResourceDataType extends DynamicDataType implements Resource {

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.BitmapResourceDataType",
			BitmapResourceDataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	public BitmapResourceDataType() {
		this(null, "BitmapResource", null);
	}

	public BitmapResourceDataType(DataTypeManager dtm) {
		this(null, "BitmapResource", dtm);
	}

	protected BitmapResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "Bitmap stored as a Resource";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "BitmapRes";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		BitmapResource bitmap = getBitmapResource(buf);
		if (bitmap == null) {
			return null;
		}

		DataImage img = bitmap.getDataImage(buf);
		if (img != null) {
			img.setDescription("<Bitmap-Image>");
		}
		return img;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return DataImage.class;
	}

	@Override
	protected final synchronized DataTypeComponent[] getAllComponents(MemBuffer buf) {
		BitmapResource bmr = getBitmapResource(buf);
		if (bmr == null) {
			return null;
		}

		try {
			bmr.getDataImage(buf);
		}
		catch (Exception e) {
			return null;
		}
		List<DataTypeComponent> comps = new ArrayList<>();
		addComponents(buf, bmr, comps);
		DataTypeComponent[] compsArray = new DataTypeComponent[comps.size()];
		comps.toArray(compsArray);
		comps = null;
		return compsArray;
	}

	protected final synchronized int addComp(DataType dataType, int length, String fieldName,
			List<DataTypeComponent> comps, int offset) {
		comps.add(new ReadOnlyDataTypeComponent(dataType, this, length, comps.size(), offset,
			fieldName, null));
		return offset + length;
	}

	protected BitmapResource getBitmapResource(MemBuffer buf) {
		try {
			return new BitmapResource(buf);
		}
		catch (IOException ioe) {
			return null;
		}
	}

	protected int addComponents(MemBuffer buf, BitmapResource bmr, List<DataTypeComponent> comps) {
		// see spec: https://msdn.microsoft.com/en-us/library/windows/desktop/dd183376%28v=vs.85%29.aspx
		//https://msdn.microsoft.com/en-us/library/windows/desktop/dd183375%28v=vs.85%29.aspx

		// Fixed-length components
		int offset = 0;
		offset = addComp(DWordDataType.dataType, 4, "size", comps, offset);       	//size of structure
		offset = addComp(DWordDataType.dataType, 4, "width", comps, offset);      	//width of bitmap in pixels
		offset = addComp(DWordDataType.dataType, 4, "height", comps, offset);  		//height of bitmap in pixels
		offset = addComp(WordDataType.dataType, 2, "planes", comps, offset);   		//number of planes - value must be a 1
		offset = addComp(WordDataType.dataType, 2, "bitCount", comps, offset); 		//number of bits per pixel													   		
		offset = addComp(DWordDataType.dataType, 4, "compression", comps, offset);  //type of compression for a compressed bottom-up bitmap (top down ones can't be compressed)
		offset = addComp(DWordDataType.dataType, 4, "sizeImage", comps, offset);
		offset = addComp(DWordDataType.dataType, 4, "XpelsPerMeter", comps, offset);
		offset = addComp(DWordDataType.dataType, 4, "YpelsPerMeter", comps, offset);
		offset = addComp(DWordDataType.dataType, 4, "clrUsed", comps, offset);
		offset = addComp(DWordDataType.dataType, 4, "clrImportant", comps, offset);

		int arraySize = bmr.getColorMapLength();
		if (arraySize > 0) {
			Array array = new ArrayDataType(ByteDataType.dataType, arraySize, 1);
			offset = addComp(array, arraySize, "ColorMap", comps, offset);
		}
		arraySize = bmr.getRawSizeImage();
		if (arraySize > 0) {
			Array array = new ArrayDataType(ByteDataType.dataType, arraySize, 1);
			offset = addComp(array, arraySize, "ImageData", comps, offset);
		}
		return offset;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<Bitmap-Image>";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "BITMAP";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new BitmapResourceDataType(dtm);
	}

}
