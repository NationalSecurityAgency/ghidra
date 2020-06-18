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
package ghidra.file.formats.android.ota_update;

/**
 * https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_consumer/payload_constants.cc
 * 
 * https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_generator/payload_file.h
 */
public final class PayloadConstants {

	public final static long kChromeOSMajorPayloadVersion = 1;

	public final static long kBrilloMajorPayloadVersion = 2;

	public final static int kMinSupportedMinorPayloadVersion = 1;
	public final static int kMaxSupportedMinorPayloadVersion = 6;

	public final static int kFullPayloadMinorVersion = 0;

	public final static int kInPlaceMinorPayloadVersion = 1;

	public final static int kSourceMinorPayloadVersion = 2;

	public final static int kOpSrcHashMinorPayloadVersion = 3;

	public final static int kBrotliBsdiffMinorPayloadVersion = 4;

	public final static int kPuffdiffMinorPayloadVersion = 5;

	public final static int kVerityMinorPayloadVersion = 6;

	public final static long kMinSupportedMajorPayloadVersion = 1;
	public final static long kMaxSupportedMajorPayloadVersion = 2;

	public final static long kMaxPayloadHeaderSize = 24;

	public final static String kPartitionNameKernel = "kernel";
	public final static String kPartitionNameRoot = "root";

	public final static String kDeltaMagic = "CrAU";

}
