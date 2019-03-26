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
package ghidra.app.util.bin.format.macho.prelink;

/**
 * Taken from:
 * http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/libkern/libkern/prelink.h
 * 
 */
public final class PrelinkConstants {

	public static final String TITLE                            = "iOS Prelink";

	public static final String kPrelinkSegment_iOS_1x           = "__PRELINK";

	public static final String kPrelinkTextSegment              = "__PRELINK_TEXT";
	public static final String kPrelinkTextSection              = "__text";

	public static final String kPrelinkStateSegment             = "__PRELINK_STATE";
	public static final String kPrelinkKernelLinkStateSection   = "__kernel";
	public static final String kPrelinkKextsLinkStateSection    = "__kexts";

	public static final String kPrelinkInfoSegment              = "__PRELINK_INFO";
	public static final String kPrelinkInfoSection              = "__info";

	public static final String kPrelinkBundlePathKey            = "_PrelinkBundlePath";
	public static final String kPrelinkExecutableKey            = "_PrelinkExecutable";
	public static final String kPrelinkExecutableLoadKey        = "_PrelinkExecutableLoadAddr";
	public static final String kPrelinkExecutableSourceKey      = "_PrelinkExecutableSourceAddr";
	public static final String kPrelinkExecutableSizeKey        = "_PrelinkExecutableSize";
	public static final String kPrelinkInfoDictionaryKey        = "_PrelinkInfoDictionary";
	public static final String kPrelinkInterfaceUUIDKey         = "_PrelinkInterfaceUUID";
	public static final String kPrelinkKmodInfoKey              = "_PrelinkKmodInfo";
	public static final String kPrelinkLinkStateKey             = "_PrelinkLinkState";
	public static final String kPrelinkLinkStateSizeKey         = "_PrelinkLinkStateSize";
	public static final String kPrelinkPersonalitiesKey         = "_PrelinkPersonalities";

	public static final String kPrelinkModuleIndexKey = "ModuleIndex";

}
