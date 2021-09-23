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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.vdex.VdexHeader;

public final class OatDexFileFactory {

	public final static OatDexFile getOatDexFile(BinaryReader reader, String oatVersion,
			Object additionalData) throws IOException {

		switch (oatVersion) {
			case OatConstants.VERSION_KITKAT_RELEASE:
				return new OatDexFile_KitKat(reader);
			case OatConstants.VERSION_LOLLIPOP_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
				return new OatDexFile_Lollipop(reader);
			case OatConstants.VERSION_MARSHMALLOW_RELEASE:
				return new OatDexFile_Marshmallow(reader);
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
				return new OatDexFile_Nougat(reader);
			case OatConstants.VERSION_OREO_RELEASE:
			case OatConstants.VERSION_OREO_DR3_RELEASE: {
				VdexHeader vdexHeader = (VdexHeader) additionalData;
				return new OatDexFile_Oreo(reader, vdexHeader);
			}
			case OatConstants.VERSION_OREO_M2_RELEASE: {
				VdexHeader vdexHeader = (VdexHeader) additionalData;
				return new OatDexFile_OreoM2(reader, vdexHeader);
			}
			case OatConstants.VERSION_PIE_RELEASE: {
				VdexHeader vdexHeader = (VdexHeader) additionalData;
				return new OatDexFile_Pie(reader, vdexHeader);
			}
			case OatConstants.VERSION_10_RELEASE: {
				VdexHeader vdexHeader = (VdexHeader) additionalData;
				return new OatDexFile_Android10(reader, vdexHeader);
			}
			case OatConstants.VERSION_11_RELEASE: {
				VdexHeader vdexHeader = (VdexHeader) additionalData;
				return new OatDexFile_Android11(reader, vdexHeader);
			}
		}
		throw new IOException("Unsupported OAT version: " + oatVersion);
	}
}
