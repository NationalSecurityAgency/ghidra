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
package ghidra.file.formats.android.versions;

import java.util.*;

public class AndroidVersionManager {

	/** Name of XML attribute in the AndroidManifest.xml file. */
	public static final String PLATFORM_BUILD_VERSION_NAME = "platformBuildVersionName";

	/** Name of XML attribute in the AndroidManifest.xml file. */
	public static final String PLATFORM_BUILD_VERSION_CODE = "platformBuildVersionCode";

	/**
	 * Returns an array of AndroidVersion's for the given API level.
	 * For example, Android API level "23" applied to versions "6.0" and "6.0.1".
	 * @param api the Android API level
	 * @return the AndroidVersion for the given API level
	 */
	public static List<AndroidVersion> getByAPI(int api) {
		List<AndroidVersion> list = new ArrayList<>();
		for (AndroidVersion androidVersion : AndroidVersion.values()) {
			if (androidVersion.getApiVersion() == api) {
				list.add(androidVersion);
			}
		}
		return list;
	}

	/**
	 * Returns the AndroidVersion for the given version number.
	 * For example, "4.0", "5.0.1", etc.
	 * @param number the Android version number
	 * @return the AndroidVersion for the given version number
	 */
	public static AndroidVersion getByNumber(String number) {
		for (AndroidVersion androidVersion : AndroidVersion.values()) {
			if (androidVersion.getVersionNumber().equals(number)) {
				return androidVersion;
			}
		}
		return AndroidVersion.UNKNOWN;
	}

	/**
	 * Returns an array of AndroidVersion's for the given version letter.
	 * For example, Android 'M' applied to versions "6.0" and "6.0.1".
	 * @param letter the Android version letter
	 * @return the AndroidVersion for the given version letter
	 */
	public static List<AndroidVersion> getByLetter(char letter) {
		List<AndroidVersion> list = new ArrayList<>();
		for (AndroidVersion androidVersion : AndroidVersion.values()) {
			if (androidVersion.getVersionLetter() == letter) {
				list.add(androidVersion);
			}
		}
		return list;
	}

	/**
	 * Returns an array of AndroidVersion's for the given version letter.
	 * For example, Android 'M' applied to versions "6.0" and "6.0.1".
	 * @param letter the Android version letter
	 * @return the AndroidVersion for the given version letter
	 */
	public static List<AndroidVersion> getByLetter(String letter) {
		if (letter == null || letter.length() == 0) {
			return Collections.emptyList();
		}
		return getByLetter(letter.charAt(0));
	}

	/**
	 * Returns an array of AndroidVersion's for the given version name.
	 * For example, Android "Marshmallow" applied to versions "6.0" and "6.0.1".
	 * @param name the Android version name
	 * @return the AndroidVersion for the given version name
	 */
	public static List<AndroidVersion> getByName(String name) {
		List<AndroidVersion> list = new ArrayList<>();
		for (AndroidVersion androidVersion : AndroidVersion.values()) {
			if (androidVersion.getVersionName().equals(name)) {
				list.add(androidVersion);
			}
		}
		return list;
	}

	/**
	 * Returns the Android Version for the given code or name.
	 * The code will represent the API version.
	 * The name can specify either the version number (eg 5.0.1), version name (eg Oreo), or version letter (eg M).
	 * The "PlatformBuildVersionCode" and "PlatformBuildVersionName" are specified 
	 * in the AndroidManifest.xml file.
	 * <pre>
	 * platformBuildVersionCode="33"
	 * platformBuildVersionName="T"
	 * </pre>
	 * @param code the PlatformBuildVersionCode specified in the AndroidManifest.xml
	 * @param name the PlatformBuildVersionName specified in the AndroidManifest.xml
	 * @return the AndroidVersion for the given PlatformBuildVersionCode or PlatformBuildVersionName
	 */
	public static AndroidVersion getByPlatformBuildVersion(String code, String name) {
		for (AndroidVersion version : AndroidVersion.values()) {
			if (version.getApiVersion() == toInteger(code)) {
				return version;
			}
			else if (version.getVersionName().equals(name)) {
				return version;
			}
			else if (version.getVersionNumber().equals(name)) {
				return version;
			}
			else if (String.valueOf(version.getVersionLetter()).equals(name)) {
				return version;
			}
		}
		return AndroidVersion.UNKNOWN;
	}

	private static int toInteger(String platformBuildVersionCode) {
		try {
			return Integer.parseInt(platformBuildVersionCode);
		}
		catch (Exception e) {
			return AndroidVersion.INVALID_API_VALUE;
		}
	}

}
