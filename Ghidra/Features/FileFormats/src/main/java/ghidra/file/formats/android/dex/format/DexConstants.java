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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.ByteProvider;

/**
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file.h
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/standard_dex_file.cc
 */
public final class DexConstants {

	//public final static String DEX_MAGIC      = "dex\n035\0";

	public final static String DEX_MAGIC_BASE = "dex\n";

	public final static int DEX_VERSION_LENGTH = 4;

	public final static String DEX_VERSION_009 = "009";

	/** Expected version string */
	public final static String DEX_VERSION_035 = "035";
	/**
	 * Dex version 036 skipped because of an old dalvik bug on some versions
	 * of android where dex files with that version number would erroneously
	 * be accepted and run. 
	 */
	public final static String DEX_VERSION_036 = "036";
	/**
	 * V037 was introduced in API LEVEL 24
	 */
	public final static String DEX_VERSION_037 = "037";
	/**
	 * Dex version 038: Android "O" and beyond.
	 * 
	 * V038 was introduced in API LEVEL 26
	 */
	public final static String DEX_VERSION_038 = "038";
	/**
	 * Dex version 039: Android "P" and beyond.
	 * 
	 * V039 was introduced in API LEVEL 28
	 */
	public final static String DEX_VERSION_039 = "039";
	/**
	 * Dex version 040: beyond Android "10" (previously known as Android "Q").
	 */
	public final static String DEX_VERSION_040 = "040";

	public final static String MACHINE = "1";

	public final static int ENDIAN_CONSTANT = 0x12345678;
	public final static int REVERSE_ENDIAN_CONSTANT = 0x78563412;

	public final static int kDexEndianConstant = 0x12345678;

	/**
	 * First Dex format version enforcing class definition ordering rules.
	 */
	public final static int kClassDefinitionOrderEnforcedVersion = 37;

	public final static int kSha1DigestSize = 20;

	public final static boolean isDexFile(ByteProvider provider) {
		try {
			byte[] bytes = provider.readBytes(0, DEX_MAGIC_BASE.length());
			return DEX_MAGIC_BASE.equals(new String(bytes));
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}
}
