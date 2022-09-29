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
package ghidra.file.formats.android.vdex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.vdex.headers.*;

public final class VdexHeaderFactory {

	/**
	 * Returns an VDEX Header for the specified version.
	 * @param reader the binary reader
	 * @return the new VDEX header
	 * @throws IOException if an error occurs creating new VDEX header
	 * @throws UnsupportedVdexVersionException when the provided version is invalid or not yet implemented.
	 */
	public static VdexHeader getVdexHeader(BinaryReader reader)
			throws IOException, UnsupportedVdexVersionException {
		String magic = reader.readAsciiString(0, VdexConstants.MAGIC.length());
		String version = reader.readAsciiString(4, 4);
		if (magic.equals(VdexConstants.MAGIC)) {
			if (VdexConstants.isSupportedVersion(version)) {
				if (version.equals(VdexConstants.VDEX_VERSION_006)) {
					return new VdexHeader_006(reader);
				}
				else if (version.equals(VdexConstants.VDEX_VERSION_010)) {
					return new VdexHeader_010(reader);
				}
				else if (version.equals(VdexConstants.VDEX_VERSION_019)) {
					return new VdexHeader_019(reader);
				}
				else if (version.equals(VdexConstants.VDEX_VERSION_021)) {
					return new VdexHeader_021(reader);
				}
				else if (version.equals(VdexConstants.VDEX_VERSION_027)) {
					return new VdexHeader_027(reader);
				}
			}
		}
		throw new UnsupportedVdexVersionException(magic, version);
	}

}
