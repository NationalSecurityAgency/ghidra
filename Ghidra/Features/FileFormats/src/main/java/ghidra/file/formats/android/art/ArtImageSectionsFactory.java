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
import ghidra.file.formats.android.art.image_sections.*;

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
			case ArtConstants.ART_VERSION_017:
				return new ImageSections_Marshmallow(reader, artHeader);
			case ArtConstants.ART_VERSION_029:
				return new ImageSections_Nougat(reader, artHeader);
			case ArtConstants.ART_VERSION_030:
				return new ImageSections_NougatMR2Pixel(reader, artHeader);
			case ArtConstants.ART_VERSION_043:
			case ArtConstants.ART_VERSION_044:
				return new ImageSections_Oreo(reader, artHeader);
			case ArtConstants.ART_VERSION_046:
				return new ImageSections_OreoMR1(reader, artHeader);
			case ArtConstants.ART_VERSION_056:
				return new ImageSections_Pie(reader, artHeader);
			case ArtConstants.ART_VERSION_074:
			case ArtConstants.ART_VERSION_085:
				return new ImageSections_Q_R(reader, artHeader);
			case ArtConstants.ART_VERSION_099:
			case ArtConstants.ART_VERSION_106:
				return new ImageSections_S_T(reader, artHeader);
		}
		throw new IOException(
			"Unsupported ART version for ImageSections: " + artHeader.getVersion());
	}
}
