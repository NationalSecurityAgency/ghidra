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

public final class OatQuickMethodHeaderFactory {

	public final static int getOatQuickMethodHeaderSize(String oatVersion) throws IOException {
		switch (oatVersion) {
			case OatConstants.VERSION_LOLLIPOP_RELEASE:
				return 12 + QuickMethodFrameInfo.SIZE;
			case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
			case OatConstants.VERSION_MARSHMALLOW_RELEASE:
				return 16 + QuickMethodFrameInfo.SIZE;
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
				return 8 + QuickMethodFrameInfo.SIZE;
			case OatConstants.VERSION_OREO_RELEASE:
			case OatConstants.VERSION_OREO_M2_RELEASE:
			case OatConstants.VERSION_OREO_DR3_RELEASE:
			case OatConstants.VERSION_PIE_RELEASE:
				return 12 + QuickMethodFrameInfo.SIZE;
			case OatConstants.VERSION_10_RELEASE:
			case OatConstants.VERSION_11_RELEASE:
				return 8;
		}
		throw new IOException("OatQuickMethodHeader unsupported OAT version: " + oatVersion);
	}

	public final static OatQuickMethodHeader getOatQuickMethodHeader(BinaryReader reader,
			String oatVersion) throws IOException {
		switch (oatVersion ) {
			case OatConstants.VERSION_LOLLIPOP_RELEASE:
				return new OatQuickMethodHeader_Lollipop(reader);
			case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
			case OatConstants.VERSION_MARSHMALLOW_RELEASE:
				return new OatQuickMethodHeader_LollipopMR1(reader);
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
				return new OatQuickMethodHeader_Nougat(reader);
			case OatConstants.VERSION_OREO_RELEASE:
			case OatConstants.VERSION_OREO_M2_RELEASE:
			case OatConstants.VERSION_OREO_DR3_RELEASE:
			case OatConstants.VERSION_PIE_RELEASE:
				return new OatQuickMethodHeader_Oreo(reader);
			case OatConstants.VERSION_10_RELEASE:
			case OatConstants.VERSION_11_RELEASE:
				return new OatQuickMethodHeader_Android10(reader);
		}
		throw new IOException("OatQuickMethodHeader unsupported OAT version: " + oatVersion);
	}
}
