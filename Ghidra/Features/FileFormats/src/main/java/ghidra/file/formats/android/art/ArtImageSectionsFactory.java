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
import ghidra.file.formats.android.art.android10.ImageSections_10;
import ghidra.file.formats.android.art.android12.ImageSections_12;
import ghidra.file.formats.android.art.marshmallow.ImageSections_Marshmallow;
import ghidra.file.formats.android.art.nougat.ImageSections_Nougat;
import ghidra.file.formats.android.art.nougat.ImageSections_NougatMR2Pixel;
import ghidra.file.formats.android.art.oreo.ImageSections_Oreo;
import ghidra.file.formats.android.art.oreo.ImageSections_OreoMR1;
import ghidra.file.formats.android.art.pie.ImageSections_Pie;

public final class ArtImageSectionsFactory {

	/**
	 * Every major version of Android has a different ImageSections enum, 
	 * this method will return the appropriate section one.
	 * @param reader the binary reader for the ART file
	 * @param artHeader the ART Header containing the sections
	 * @returns the ImageSections for the specified ART version
	 */
	public static ArtImageSections getArtImageSections(BinaryReader reader, ArtHeader artHeader)
			throws IOException {
		switch (artHeader.getVersion()) {
			case ArtConstants.VERSION_MARSHMALLOW_RELEASE:
				return new ImageSections_Marshmallow(reader, artHeader);
			case ArtConstants.VERSION_NOUGAT_RELEASE:
				return new ImageSections_Nougat(reader, artHeader);
			case ArtConstants.VERSION_NOUGAT_MR2_PIXEL_RELEASE:
				return new ImageSections_NougatMR2Pixel(reader, artHeader);
			case ArtConstants.VERSION_OREO_RELEASE:
			case ArtConstants.VERSION_OREO_DR1_RELEASE:
				return new ImageSections_Oreo(reader, artHeader);
			case ArtConstants.VERSION_OREO_MR1_RELEASE:
				return new ImageSections_OreoMR1(reader, artHeader);
			case ArtConstants.VERSION_PIE_RELEASE:
				return new ImageSections_Pie(reader, artHeader);
			case ArtConstants.VERSION_10_RELEASE:
			case ArtConstants.VERSION_11_RELEASE:
				return new ImageSections_10(reader, artHeader);
			case ArtConstants.VERSION_12_RELEASE:
				return new ImageSections_12(reader, artHeader);
		}
		throw new IOException(
			"Unsupported ART version for ImageSections: " + artHeader.getVersion());
	}
}
