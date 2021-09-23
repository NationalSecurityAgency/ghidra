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
package ghidra.file.formats.android.art.oreo;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.file.formats.android.art.ArtImageSections;
import ghidra.file.formats.android.art.nougat.ArtHeader_NougatMR2Pixel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/oreo-release/runtime/image.h
 */
public class ArtHeader_Oreo extends ArtHeader_NougatMR2Pixel {

	public ArtHeader_Oreo(BinaryReader reader) throws IOException {
		super(reader);
	}

	protected ArtImageSections getImageSections(BinaryReader reader) {
		return new ImageSections_Oreo(reader, this);
	}

	@Override
	public int getArtMethodCountForVersion() {
		return ImageMethod_Oreo.kImageMethodsCount.ordinal();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		String className = StructConverterUtil.parseName(ArtHeader_Oreo.class);
		try {
			structure.setName(className);
		}
		catch (InvalidNameException e) {
			//ignore
		}
		return structure;
	}

}
