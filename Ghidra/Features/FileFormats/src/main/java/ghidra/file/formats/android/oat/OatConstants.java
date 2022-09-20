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

	/** https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat.cc#24 */
	public final static String VERSION_KITKAT_RELEASE             = "007";
	/** https://android.googlesource.com/platform/art/+/refs/heads/kitkat-dev/runtime/oat.cc#24 */
	public final static String version_kitkat_dev                 = "008"; 
	/** https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/oat.cc#25 */
	public final static String VERSION_LOLLIPOP_RELEASE           = "039";
	/** https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-release/runtime/oat.cc#25 */
	public final static String VERSION_LOLLIPOP_MR1_FI_RELEASE    = "045";
	/** https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat.cc#27 */
	public final static String VERSION_LOLLIPOP_WEAR_RELEASE      = "051";
	/** https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/oat.h#34 */
	public final static String VERSION_MARSHMALLOW_RELEASE        = "064";
	/** https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/oat.h#34 */
	public final static String VERSION_NOUGAT_RELEASE             = "079";
	/** https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-2/runtime/oat.h#34 */
	public final static String version_n_iot_preview_2            = "083";
	/** https://android.googlesource.com/platform/art/+/refs/heads/nougat-mr1-release/runtime/oat.h#34 */
	public final static String VERSION_NOUGAT_MR1_RELEASE         = "088";
	/** https://android.googlesource.com/platform/art/+/refs/heads/o-preview/runtime/oat.h#34 */
	public final static String version_o_preview                  = "114";
	/** https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat.h#34 */
	public final static String VERSION_OREO_RELEASE               = "124";
	/** https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-4/runtime/oat.h#34 */
	public final static String version_n_iot_preview_4            = "125";
	/** https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/oat.h#34 */
	public final static String VERSION_OREO_DR3_RELEASE           = "126";
	/** https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/oat.h#34 */
	public final static String VERSION_OREO_M2_RELEASE            = "131";
	/** https://android.googlesource.com/platform/art/+/refs/heads/o-iot-preview-5/runtime/oat.h#34 */
	public final static String version_o_iot_preview_5            = "132";
	/** https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-6/runtime/oat.h#34 */
	public final static String version_o_mr1_iot_preview_6        = "135";
	/** https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/oat.h#34 */
	public final static String VERSION_PIE_RELEASE                = "138";
	/** https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-7/runtime/oat.h#34 */
	public final static String version_o_mr1_iot_preview_7        = "139";
	/** https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-8/runtime/oat.h#34 */
	public final static String version_o_mr1_iot_preview_8        = "140";
	/** https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.0/runtime/oat.h#34 */
	public final static String version_o_mr1_iot_release_1_0_0    = "141";
	/** https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.1/runtime/oat.h#34 */
	public final static String version_o_mr1_iot_release_1_0_1    = "146";
	/** https://android.googlesource.com/platform/art/+/refs/tags/android-n-iot-release-polk-at1/runtime/oat.h#34 */
	public final static String version_n_iot_release_polk_at1     = "147";
	/** https://android.googlesource.com/platform/art/+/refs/tags/android-q-preview-1/runtime/oat.h#33 */
	public final static String version_q_preview_1                = "166";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/oat.h#34 */
	public final static String VERSION_10_RELEASE                 = "170";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/oat.h#34 */
	public final static String VERSION_11_RELEASE                 = "183";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/oat.h#36 */
	public final static String VERSION_12_RELEASE                 = "195";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-4/runtime/oat.h#36 */
	public final static String VERSION_S_BETA4                    = "197";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-preview-1/runtime/oat.h#36 */
	public final static String VERSION_S_V2_PREVIEW               = "199";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android-t-preview-1/runtime/oat.h#36 */
	public final static String VERSION_T_PREVIEW_1                = "220";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-beta-3/runtime/oat.h#36 */
	public final static String VERSION_S_V2_BETA2                 = "223";
	/** https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/oat.h#36 */
	public final static String VERSION_13_RELEASE                 = "225";
	/** https://android.googlesource.com/platform/art/+/master/runtime/oat.h#36 */
	public final static String VERSION_227						  = "227";

	/**
	 * This array contains versions that have been actively tested and verified.
	 * All other versions will be considered unsupported until tested on exemplar firmware.
	 */
	public final static String [] SUPPORTED_VERSIONS = new String [] {
		VERSION_KITKAT_RELEASE,
		VERSION_LOLLIPOP_RELEASE,
		VERSION_LOLLIPOP_MR1_FI_RELEASE,
		VERSION_LOLLIPOP_WEAR_RELEASE,
		VERSION_MARSHMALLOW_RELEASE,
		VERSION_NOUGAT_RELEASE,
		VERSION_NOUGAT_MR1_RELEASE,
		VERSION_OREO_RELEASE,
		VERSION_OREO_DR3_RELEASE,
		VERSION_OREO_M2_RELEASE,
		VERSION_PIE_RELEASE,
		VERSION_10_RELEASE,
		VERSION_11_RELEASE,
		VERSION_12_RELEASE,
		VERSION_S_V2_PREVIEW,
		VERSION_T_PREVIEW_1,
		VERSION_S_V2_BETA2,
		VERSION_13_RELEASE,
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
