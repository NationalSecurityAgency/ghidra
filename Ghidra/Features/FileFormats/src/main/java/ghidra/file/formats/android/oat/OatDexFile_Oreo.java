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

/**
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat_file.h#444
 */
class OatDexFile_Oreo extends OatDexFile_Nougat {

	private VdexHeader vdexHeader;

	OatDexFile_Oreo(BinaryReader reader, VdexHeader vdexHeader) throws IOException {
		super(reader);
		this.vdexHeader = vdexHeader;
		if (vdexHeader != null) {
			for (int i = 0; i < vdexHeader.getDexChecksums().length; ++i) {
				if (vdexHeader.getDexChecksums()[i] == getDexFileChecksum()) {
					dexHeader = vdexHeader.getDexHeaderList().get(i);
				}
			}
		}
	}

	public VdexHeader getVdexHeader() {
		return vdexHeader;
	}

	@Override
	public boolean isDexHeaderExternal() {
		return true;
	}

}
