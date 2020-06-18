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

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.art.android10.ArtHeader_10;
import ghidra.file.formats.android.art.android11.ArtHeader_11;
import ghidra.file.formats.android.art.kitkat.ArtHeader_KitKat;
import ghidra.file.formats.android.art.lollipop.ArtHeader_Lollipop;
import ghidra.file.formats.android.art.lollipop.ArtHeader_LollipopMR1WFC;
import ghidra.file.formats.android.art.marshmallow.ArtHeader_Marshmallow;
import ghidra.file.formats.android.art.nougat.ArtHeader_Nougat;
import ghidra.file.formats.android.art.nougat.ArtHeader_NougatMR2Pixel;
import ghidra.file.formats.android.art.oreo.ArtHeader_Oreo;
import ghidra.file.formats.android.art.oreo.ArtHeader_OreoMR1;
import ghidra.file.formats.android.art.pie.ArtHeader_Pie;

public final class ArtFactory {

	/**
	 * Returns an ArtHeader of the correct version.
	 * @param reader the BinaryReader to the ART header
	 * @return the specific version of the ART header
	 * @throws IOException should an error occur during reading or parsing
	 * @throws UnsupportedArtVersionException when the provided version is invalid or not yet implemented.
	 */
	public final static ArtHeader newArtHeader(BinaryReader reader)
			throws IOException, UnsupportedArtVersionException {
		String magic = new String(reader.readByteArray(0, ArtConstants.MAGIC.length()));
		String version = reader.readAsciiString(4, 4);
		if (magic.equals(ArtConstants.MAGIC)) {
			if (ArtConstants.isSupportedVersion(version)) {
				switch (version ) {
					case ArtConstants.VERSION_KITKAT_RELEASE:
						return new ArtHeader_KitKat(reader);
					case ArtConstants.VERSION_LOLLIPOP_RELEASE:
						return new ArtHeader_Lollipop(reader);
					case ArtConstants.VERSION_LOLLIPOP_MR1_WFC_RELEASE:
						return new ArtHeader_LollipopMR1WFC(reader);
					case ArtConstants.VERSION_MARSHMALLOW_RELEASE:
						return new ArtHeader_Marshmallow(reader);
					case ArtConstants.VERSION_NOUGAT_RELEASE:
						return new ArtHeader_Nougat(reader);
					case ArtConstants.VERSION_NOUGAT_MR2_PIXEL_RELEASE:
						return new ArtHeader_NougatMR2Pixel(reader);
					case ArtConstants.VERSION_OREO_RELEASE:
						return new ArtHeader_Oreo(reader);
					case ArtConstants.VERSION_OREO_DR1_RELEASE:
						return new ArtHeader_Oreo(reader);//v043 and v044 are same format
					case ArtConstants.VERSION_OREO_MR1_RELEASE:
						return new ArtHeader_OreoMR1(reader);
					case ArtConstants.VERSION_PIE_RELEASE:
						return new ArtHeader_Pie(reader);
					case ArtConstants.VERSION_10_RELEASE:
						return new ArtHeader_10(reader);
					case ArtConstants.VERSION_11_RELEASE:
						return new ArtHeader_11(reader);
				}
			}
		}
		throw new UnsupportedArtVersionException(magic, version);
	}

}
