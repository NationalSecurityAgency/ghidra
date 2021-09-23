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

public final class OatMethodOffsetsFactory {

	public final static OatMethodOffsets getOatMethodOffsets(BinaryReader reader, String oatVersion)
			throws IOException {
		if (oatVersion.equals(OatConstants.VERSION_KITKAT_RELEASE)) {
			return new OatMethodOffsets_KitKat(reader);
		}
		else if (oatVersion.equals(OatConstants.VERSION_LOLLIPOP_RELEASE)) {
			return new OatMethodOffsets_Lollipop(reader);
		}
		else {
			return new OatMethodOffsets(reader);
		}
	}

}
