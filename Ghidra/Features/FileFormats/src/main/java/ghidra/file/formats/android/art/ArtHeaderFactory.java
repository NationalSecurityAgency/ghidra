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
import ghidra.file.formats.android.art.headers.*;

public final class ArtHeaderFactory {

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
				switch (version) {
					case ArtConstants.ART_VERSION_005:
						return new ArtHeader_005(reader);
					case ArtConstants.ART_VERSION_009:
						return new ArtHeader_009(reader);
					case ArtConstants.ART_VERSION_012:
						return new ArtHeader_012(reader);
					case ArtConstants.ART_VERSION_017:
						return new ArtHeader_017(reader);
					case ArtConstants.ART_VERSION_029:
						return new ArtHeader_029(reader);
					case ArtConstants.ART_VERSION_030:
						return new ArtHeader_030(reader);
					case ArtConstants.ART_VERSION_043:
						return new ArtHeader_043(reader);
					case ArtConstants.ART_VERSION_044:
						return new ArtHeader_044(reader);
					case ArtConstants.ART_VERSION_046:
						return new ArtHeader_046(reader);
					case ArtConstants.ART_VERSION_056:
						return new ArtHeader_056(reader);
					case ArtConstants.ART_VERSION_074:
						return new ArtHeader_074(reader);
					case ArtConstants.ART_VERSION_085:
						return new ArtHeader_085(reader);
					case ArtConstants.ART_VERSION_099:
						return new ArtHeader_099(reader);
					case ArtConstants.ART_VERSION_106:
						return new ArtHeader_106(reader);
				}
			}
		}
		throw new UnsupportedArtVersionException(magic, version);
	}

}
