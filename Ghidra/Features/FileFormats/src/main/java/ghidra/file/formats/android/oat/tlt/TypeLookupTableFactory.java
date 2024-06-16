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
package ghidra.file.formats.android.oat.tlt;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.file.formats.android.oat.UnsupportedOatVersionException;

public final class TypeLookupTableFactory {

	public final static TypeLookupTable getTypeLookupTable(BinaryReader reader, String oatVersion)
			throws IOException {

		switch (oatVersion) {
			case OatConstants.OAT_VERSION_079:
			case OatConstants.OAT_VERSION_088:
				return new TypeLookupTable_Nougat(reader);
			case OatConstants.OAT_VERSION_124:
			case OatConstants.OAT_VERSION_131:
			case OatConstants.OAT_VERSION_126:
				return new TypeLookupTable_Oreo(reader);
			case OatConstants.OAT_VERSION_138:
				return new TypeLookupTable_Pie(reader);
			case OatConstants.OAT_VERSION_170:
				return new TypeLookupTable_Q(reader);
			case OatConstants.OAT_VERSION_183:
				return new TypeLookupTable_R(reader);
			case OatConstants.OAT_VERSION_195:
			case OatConstants.OAT_VERSION_199:
			case OatConstants.OAT_VERSION_220:
			case OatConstants.OAT_VERSION_223:
			case OatConstants.OAT_VERSION_225:
				return new TypeLookupTable_S_T(reader);
			default:
				throw new IOException(new UnsupportedOatVersionException(
					"Unsupported TypeLookupTable for OAT version " + oatVersion));
		}
	}

}
