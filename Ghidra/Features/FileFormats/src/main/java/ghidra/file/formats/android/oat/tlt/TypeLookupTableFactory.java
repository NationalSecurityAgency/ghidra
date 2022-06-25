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
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
				return new TypeLookupTable_Nougat(reader);
			case OatConstants.VERSION_OREO_RELEASE:
			case OatConstants.VERSION_OREO_M2_RELEASE:
			case OatConstants.VERSION_OREO_DR3_RELEASE:
				return new TypeLookupTable_Oreo(reader);
			case OatConstants.VERSION_PIE_RELEASE:
				return new TypeLookupTable_Pie(reader);
			case OatConstants.VERSION_10_RELEASE:
				return new TypeLookupTable_Android10(reader);
			case OatConstants.VERSION_11_RELEASE:
				return new TypeLookupTable_Android11(reader);
			case OatConstants.VERSION_12_RELEASE:
			case OatConstants.VERSION_S_V2_PREVIEW:
				return new TypeLookupTable_Android12(reader);
			default:
				throw new IOException(new UnsupportedOatVersionException(
					"Unsupported TypeLookupTable for OAT version " + oatVersion));
		}
	}

}
