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
package ghidra.file.formats.android.art;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class ArtImageSection implements StructConverter {
	private int offset_;
	private int size_;

	public ArtImageSection(BinaryReader reader) throws IOException {
		offset_ = reader.readNextInt();
		size_ = reader.readNextInt();
	}

	public int getOffset() {
		return offset_;
	}

	public int getSize() {
		return size_;
	}

	public int getEnd() {
		return offset_ + size_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(ArtImageSection.class);
		dataType.setCategoryPath(new CategoryPath("/art"));
		return dataType;
	}

}
