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
package ghidra.app.util.bin.format.pe.rich;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;

class MSRichProductInfoDataType extends StructureDataType {

	private final CompId compid;

	public MSRichProductInfoDataType(CompId compid) {
		this(compid, null);
	}

	public MSRichProductInfoDataType(CompId compid, DataTypeManager dtm) {
		super(new CategoryPath("/PE"), "ProductInfo", 0, dtm);
		this.compid = compid;
		initialize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return false;
	}

	@Override
	public MSRichProductInfoDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MSRichProductInfoDataType(compid, dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "Product Info";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getDescription() {
		return "Product Info";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return compid;
	}

	private void initialize() {
		add(new MSRichProductIDDataType(compid), 2, "product", null);
		add(new MSRichProductBuildNumberDataType(compid), 2, "buildNumber", null);
	}
}
