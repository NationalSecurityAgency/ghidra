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
 * https://android.googlesource.com/platform/art/+/marshmallow-mr3-release/runtime/oat.h
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

	public final static String VERSION_KITKAT_RELEASE             = "007"; 
	public final static String version_kitkat_dev                 = "008"; 
	public final static String VERSION_LOLLIPOP_RELEASE           = "039";
	public final static String VERSION_LOLLIPOP_MR1_FI_RELEASE    = "045";
	public final static String VERSION_LOLLIPOP_WEAR_RELEASE      = "051";
	public final static String VERSION_MARSHMALLOW_RELEASE        = "064";
	public final static String VERSION_NOUGAT_RELEASE             = "079";
	public final static String version_n_iot_preview_2            = "083";
	public final static String VERSION_NOUGAT_MR1_RELEASE         = "088";
	public final static String version_o_preview                  = "114";
	public final static String VERSION_OREO_RELEASE               = "124";
	public final static String version_n_iot_preview_4            = "125";
	public final static String VERSION_OREO_DR3_RELEASE           = "126";
	public final static String VERSION_OREO_M2_RELEASE            = "131";
	public final static String version_o_iot_preview_5            = "132";
	public final static String version_134                        = "134";
	public final static String version_o_mr1_iot_preview_6        = "135";
	public final static String VERSION_PIE_RELEASE                = "138";
	public final static String version_o_mr1_iot_preview_7        = "139";
	public final static String version_o_mr1_iot_preview_8        = "140";
	public final static String version_o_mr1_iot_release_1_0_0    = "141";
	public final static String version_o_mr1_iot_release_1_0_1    = "146";
	public final static String version_n_iot_release_polk_at1     = "147";
	public final static String version_q_preview_1                = "166";
	public final static String VERSION_10_RELEASE                 = "170";
	public final static String VERSION_11_RELEASE                 = "183";
	public final static String VERSION_12_RELEASE                 = "195";
	public final static String VERSION_S_V2_PREVIEW               = "199";

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
