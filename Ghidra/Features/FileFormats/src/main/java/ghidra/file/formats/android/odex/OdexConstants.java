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
package ghidra.file.formats.android.odex;

import ghidra.app.util.bin.ByteProvider;

/**
 * 
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/kitkat-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/lollipop-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/marshmallow-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/nougat-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/oreo-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/pie-release/libdex/DexFile.h
 * https://android.googlesource.com/platform/dalvik/+/refs/heads/android10-release/libdex/DexFile.h
 * 
 * Removed in Android11
 * 
 */
public final class OdexConstants {

	public final static String ODEX_MAGIC_35 = "dey\n035\0";
	public final static String ODEX_MAGIC_36 = "dey\n036\0";
	public final static String ODEX_MAGIC_37 = "dey\n037\0";

	public final static int ODEX_MAGIC_LENGTH = ODEX_MAGIC_36.length();

	public final static boolean isOdexFile(ByteProvider provider) {
		try {
			String magic = new String(provider.readBytes(0, ODEX_MAGIC_LENGTH));
			return ODEX_MAGIC_35.equals(new String(magic)) ||
				ODEX_MAGIC_36.equals(new String(magic));
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}
}
