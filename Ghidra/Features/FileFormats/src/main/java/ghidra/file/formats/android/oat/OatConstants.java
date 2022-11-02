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

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;

/**
 * https://android.googlesource.com/platform/art/+/master/runtime/oat.h
 */
public final class OatConstants {
	//@formatter:off

	public final static String MAGIC = "oat\n";

	public final static String SYMBOL_OAT_BSS                      =  "oatbss";
	public final static String SYMBOL_OAT_BSS_LASTWORD             =  "oatbsslastword";
	public final static String SYMBOL_OAT_BSS_METHODS              =  "oatbssmethods";
	public final static String SYMBOL_OAT_BSS_ROOTS                =  "oatbssroots";
	public final static String SYMBOL_OAT_DATA                     =  "oatdata";
	public final static String SYMBOL_OAT_DATA_BIMGRELRO           =  "oatdatabimgrelro";
	public final static String SYMBOL_OAT_DATA_BIMGRELRO_LASTWORD  =  "oatdatabimgrelrolastword";
	public final static String SYMBOL_OAT_DEX                      =  "oatdex";
	public final static String SYMBOL_OAT_DEX_LASTWORD             =  "oatdexlastword";
	public final static String SYMBOL_OAT_EXEC                     =  "oatexec";
	public final static String SYMBOL_OAT_LASTWORD                 =  "oatlastword";

	public final static String OAT_SECTION_NAME = ElfSectionHeaderConstants.dot_rodata;

	public final static String DOT_OAT_PATCHES_SECTION_NAME = ".oat_patches";

	/* Keys from the OAT header "key/value" store. */
	public final static String kApexVersionsKey           = "apex-versions";
	public final static String kBootClassPathKey          = "bootclasspath";
	public final static String kBootClassPathChecksumsKey = "bootclasspath-checksums";
	public final static String kClassPathKey              = "classpath";
	public final static String kCompilationReasonKey      = "compilation-reason";
	public final static String kCompilerFilter            = "compiler-filter";
	public final static String kConcurrentCopying         = "concurrent-copying";	
	public final static String kDebuggableKey             = "debuggable";
	public final static String kDex2OatCmdLineKey         = "dex2oat-cmdline";
	public final static String kDex2OatHostKey            = "dex2oat-host";
	public final static String kHasPatchInfoKey           = "has-patch-info";
	public final static String kImageLocationKey          = "image-location";
	public final static String kNativeDebuggableKey       = "native-debuggable";
	public final static String kPicKey                    = "pic";
	public final static String kRequiresImage             = "requires-image";

	/** Boolean value used in the Key/Value store for TRUE. */
	public final static String kTrueValue  = "true";
	/** Boolean value used in the Key/Value store for FALSE. */
	public final static String kFalseValue = "false";

	// * * * * * * * * * * * * * * * * * * * * * * * *
	// NOTE: we plan to only support RELEASE versions...
	// Upper case indicates supported version.

	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat.cc#24">kitkat-release/runtime/oat.cc</a> */
	public final static String OAT_VERSION_007 = "007";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-dev/runtime/oat.cc#24">kitkat-dev/runtime/oat.cc</a> */
	public final static String oat_version_008 = "008"; 
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/oat.cc#25">lollipop-release/runtime/oat.cc</a> */
	public final static String OAT_VERSION_039 = "039";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-release/runtime/oat.cc#25">lollipop-mr1-release/runtime/oat.cc</a> */
	public final static String OAT_VERSION_045 = "045";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat.cc#27">lollipop-wear-release/runtime/oat.cc</a> */
	public final static String OAT_VERSION_051 = "051";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/oat.h#34">marshmallow-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_064 = "064";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/oat.h#34">nougat-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_079 = "079";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-2/runtime/oat.h#34">n-iot-preview-2/runtime/oat.h</a> */
	public final static String oat_version_083 = "083";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/nougat-mr1-release/runtime/oat.h#34">nougat-mr1-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_088 = "088";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-preview/runtime/oat.h#34">o-preview/runtime/oat.h</a> */
	public final static String oat_version_114 = "114";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat.h#34">oreo-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_124 = "124";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-4/runtime/oat.h#34">n-iot-preview-4/runtime/oat.h</a> */
	public final static String oat_version_125 = "125";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/oat.h#34">oreo-dr3-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_126 = "126";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/oat.h#34">oreo-m2-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_131 = "131";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-iot-preview-5/runtime/oat.h#34">o-iot-preview-5/runtime/oat.h</a> */
	public final static String oat_version_132 = "132";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-6/runtime/oat.h#34">o-mr1-iot-preview-6/runtime/oat.h</a> */
	public final static String oat_version_135 = "135";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/oat.h#34">pie-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_138 = "138";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-7/runtime/oat.h#34">o-mr1-iot-preview-7/runtime/oat.h</a> */
	public final static String oat_version_139 = "139";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-8/runtime/oat.h#34">o-mr1-iot-preview-8/runtime/oat.h</a> */
	public final static String oat_version_140 = "140";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.0/runtime/oat.h#34">android-o-mr1-iot-release-1.0.0/runtime/oat.h</a> */
	public final static String oat_version_141 = "141";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.1/runtime/oat.h#34">android-o-mr1-iot-release-1.0.1/runtime/oat.h</a> */
	public final static String oat_version_146 = "146";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/tags/android-n-iot-release-polk-at1/runtime/oat.h#34">android-n-iot-release-polk-at1/runtime/oat.h</a> */
	public final static String oat_version_147 = "147";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/tags/android-q-preview-1/runtime/oat.h#33">android-q-preview-1/runtime/oat.h</a> */
	public final static String oat_version_166 = "166";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/oat.h#3"4>android10-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_170 = "170";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/oat.h#34">android11-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_183 = "183";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/oat.h#3"6>android12-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_195 = "195";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-4/runtime/oat.h#36">android-s-beta-4/runtime/oat.h</a> */
	public final static String oat_version_197 = "197";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-preview-1/runtime/oat.h#36">android-s-v2-preview-1/runtime/oat.h</a> */
	public final static String OAT_VERSION_199 = "199";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-t-preview-1/runtime/oat.h#36">android-t-preview-1/runtime/oat.h</a> */
	public final static String OAT_VERSION_220 = "220";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-beta-3/runtime/oat.h#36">android-s-v2-beta-3/runtime/oat.h</a> */
	public final static String OAT_VERSION_223 = "223";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/oat.h#36">android13-release/runtime/oat.h</a> */
	public final static String OAT_VERSION_225 = "225";
	/** <a href="https://android.googlesource.com/platform/art/+/master/runtime/oat.h#36">master/runtime/oat.h</a> */
	public final static String OAT_VERSION_227 = "227";

	/**
	 * This array contains versions that have been actively tested and verified.
	 * All other versions will be considered unsupported until tested on exemplar firmware.
	 */
	public final static String [] SUPPORTED_VERSIONS = new String [] {
		OAT_VERSION_007,
		OAT_VERSION_039,
		OAT_VERSION_045,
		OAT_VERSION_051,
		OAT_VERSION_064,
		OAT_VERSION_079,
		OAT_VERSION_088,
		OAT_VERSION_124,
		OAT_VERSION_126,
		OAT_VERSION_131,
		OAT_VERSION_138,
		OAT_VERSION_170,
		OAT_VERSION_183,
		OAT_VERSION_195,
		OAT_VERSION_199,
		OAT_VERSION_220,
		OAT_VERSION_223,
		OAT_VERSION_225,
	};

	//@formatter:on

	/**
	 * Returns true if the given OAT version string is supported by Ghidra.
	 * @param version the OAT version
	 * @return true if the given OAT version string is supported
	 */
	public final static boolean isSupportedVersion(String version) {
		for (String supportedVersion : SUPPORTED_VERSIONS) {
			if (supportedVersion.equals(version)) {
				return true;
			}
		}
		return false;
	}

}
