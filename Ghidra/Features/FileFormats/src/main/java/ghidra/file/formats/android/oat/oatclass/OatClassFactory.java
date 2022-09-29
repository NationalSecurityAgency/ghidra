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
			case OatConstants.OAT_VERSION_007:
				return new OatClass_KitKat(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_039:
			case OatConstants.OAT_VERSION_045:
			case OatConstants.OAT_VERSION_051:
				return new OatClass_Lollipop(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_064:
				return new OatClass_Marshmallow(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_079:
			case OatConstants.OAT_VERSION_088:
				return new OatClass_Nougat(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_124:
				return new OatClass_Oreo(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_131:
				return new OatClass_OreoM2(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_138:
				return new OatClass_Pie(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_170:
				return new OatClass_Q(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_183:
				return new OatClass_R(reader, classDataItem, oatVersion);
			case OatConstants.OAT_VERSION_195:
			case OatConstants.OAT_VERSION_199:
			case OatConstants.OAT_VERSION_220:
			case OatConstants.OAT_VERSION_223:
			case OatConstants.OAT_VERSION_225:
				return new OatClass_S_T(reader, classDataItem, oatVersion);
			default:
				throw new UnsupportedOatVersionException(
					"OatClass not supported for OAT Version: " + oatVersion);
		}
	}
}
