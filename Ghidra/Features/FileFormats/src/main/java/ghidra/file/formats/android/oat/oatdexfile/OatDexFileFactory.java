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
package ghidra.file.formats.android.oat.oatdexfile;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.file.formats.android.oat.bundle.OatBundle;

public final class OatDexFileFactory {

	public final static OatDexFile getOatDexFile(BinaryReader reader, String oatVersion,
			OatBundle bundle) throws IOException {

		switch (oatVersion) {
			case OatConstants.OAT_VERSION_007:
				return new OatDexFile_KitKat(reader);
			case OatConstants.OAT_VERSION_039:
			case OatConstants.OAT_VERSION_045:
			case OatConstants.OAT_VERSION_051:
				return new OatDexFile_Lollipop(reader);
			case OatConstants.OAT_VERSION_064:
				return new OatDexFile_Marshmallow(reader);
			case OatConstants.OAT_VERSION_079:
			case OatConstants.OAT_VERSION_088:
				return new OatDexFile_Nougat(reader);
			case OatConstants.OAT_VERSION_124:
			case OatConstants.OAT_VERSION_126:
				return new OatDexFile_Oreo(reader, bundle);
			case OatConstants.OAT_VERSION_131:
				return new OatDexFile_OreoM2(reader, bundle);
			case OatConstants.OAT_VERSION_138:
				return new OatDexFile_Pie(reader, bundle);
			case OatConstants.OAT_VERSION_170:
				return new OatDexFile_Q(reader, bundle);
			case OatConstants.OAT_VERSION_183:
				return new OatDexFile_R(reader, bundle);
			case OatConstants.OAT_VERSION_195:
			case OatConstants.OAT_VERSION_199:
			case OatConstants.OAT_VERSION_220:
			case OatConstants.OAT_VERSION_223:
			case OatConstants.OAT_VERSION_225:
				return new OatDexFile_S_T(reader, bundle);
		}

		throw new IOException("Unsupported OAT version: " + oatVersion);
	}
}
