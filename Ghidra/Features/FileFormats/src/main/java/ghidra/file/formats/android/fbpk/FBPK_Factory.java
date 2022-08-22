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
package ghidra.file.formats.android.fbpk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.fbpk.v1.FBPKv1;
import ghidra.file.formats.android.fbpk.v2.FBPKv2;

public class FBPK_Factory {
	public final static FBPK getFBPK(BinaryReader reader)
			throws IOException {

		if (reader.length() > 8) {
			int magic = reader.readInt(0);
			int version = reader.readInt(4);

			if (magic == FBPK_Constants.FBPK_MAGIC) {
				switch (version) {
					case FBPK_Constants.VERSION_1: {
						return new FBPKv1(reader);
					}
					case FBPK_Constants.VERSION_2: {
						return new FBPKv2(reader);
					}
				}
			}
			throw new IOException("Unsupported " + FBPK_Constants.FBPK + " version: " + version);
		}
		throw new IOException("Invalid " + FBPK_Constants.FBPK + " file");
	}
}
