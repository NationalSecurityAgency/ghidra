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
package ghidra.file.formats.android.oat.oatclass;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.format.ClassDataItem;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.file.formats.android.oat.UnsupportedOatVersionException;

public class OatClassFactory {

	public static OatClass getOatClass(BinaryReader reader, ClassDataItem classDataItem,
			String oatVersion) throws IOException, UnsupportedOatVersionException {

		switch (oatVersion) {
			case OatConstants.VERSION_KITKAT_RELEASE:
				return new OatClass_KitKat(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_LOLLIPOP_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
				return new OatClass_Lollipop(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_MARSHMALLOW_RELEASE:
				return new OatClass_Marshmallow(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
				return new OatClass_Nougat(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_OREO_RELEASE:
				return new OatClass_Oreo(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_OREO_M2_RELEASE:
				return new OatClass_OreoM2(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_PIE_RELEASE:
				return new OatClass_Pie(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_10_RELEASE:
				return new OatClass_Android10(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_11_RELEASE:
				return new OatClass_Android11(reader, classDataItem, oatVersion);
			case OatConstants.VERSION_12_RELEASE:
			case OatConstants.VERSION_S_V2_PREVIEW:
				return new OatClass_Android12(reader, classDataItem, oatVersion);
			default:
				throw new UnsupportedOatVersionException(
					"OatClass not supported for OAT Version: " + oatVersion);
		}
	}
}
