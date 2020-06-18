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
package ghidra.file.formats.android.prof;

import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;

/**
 * Android Profiling (.PROF) files.
 * 
 * "current profiles are stored next to the dex files under the oat folder"
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/android11-release/libprofile/profile/profile_compilation_info.cc
 * 
 * https://android.googlesource.com/platform/frameworks/native/+/master/cmds/installd/utils.cpp
 * https://android.googlesource.com/platform/frameworks/native/+/master/cmds/installd/dexopt.cpp
 * 
 */
public final class ProfileConstants {

	public final static byte[] kProfileMagic = { 'p', 'r', 'o', '\0' };

	public final static int kProfileMagicLength = kProfileMagic.length;

	public final static byte[] kProfileVersion_008 = { '0', '0', '8', '\0' };
	public final static byte[] kProfileVersion_009 = { '0', '0', '9', '\0' };
	/**
	 * Android 10
	 * Android 11
	 */
	public final static byte[] kProfileVersion_010 = { '0', '1', '0', '\0' };

	public final static byte[] kProfileVersionForBootImage_012 = { '0', '1', '2', '\0' };

	public final static String kDexMetadataProfileEntry = "primary.prof";

	public final static byte[] kProfileVersionWithCounters = { '5', '0', '0', '\0' };

	/**
	 * Converts the byte array into String and trims it.
	 */
	public final static String toString(byte[] bytes) {
		return new String(bytes).trim();
	}

	public static boolean isProfile(ByteProvider provider) {
		try {
			byte[] magicBytes = provider.readBytes(0, kProfileMagicLength);
			if (Arrays.equals(magicBytes, kProfileMagic)) {
				byte[] versionBytes =
					provider.readBytes(kProfileMagicLength, kProfileVersion_010.length);
				if (Arrays.equals(versionBytes, kProfileVersion_010)) {
					return true;
				}
			}
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}
}
