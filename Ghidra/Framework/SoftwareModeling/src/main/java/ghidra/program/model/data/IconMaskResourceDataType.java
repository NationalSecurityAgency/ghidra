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

public class IconMaskResourceDataType extends IconResourceDataType {
	private final static long serialVersionUID = 1;

	public IconMaskResourceDataType() {
		this(null, "IconMaskResource", null);
	}

	public IconMaskResourceDataType(DataTypeManager dtm) {
		this(null, "IconMaskResource", dtm);
	}

	protected IconMaskResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "Icon with Mask stored as a Resource";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "IconMaskRes";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new IconMaskResourceDataType(dtm);
	}
}
