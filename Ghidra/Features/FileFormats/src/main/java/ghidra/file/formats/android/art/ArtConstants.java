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
package ghidra.file.formats.android.art;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * https://android.googlesource.com/platform/art/+/master/runtime/image.cc
 */
public final class ArtConstants {

	public final static String ART_NAME = "Android Runtime (ART)";

	public final static String MAGIC = "art\n";

	public final static int VERSION_LENGTH = 4;

	public final static String VERSION_KITKAT_RELEASE = "005";
	public final static String VERSION_LOLLIPOP_RELEASE = "009";
	public final static String VERSION_LOLLIPOP_MR1_WFC_RELEASE = "012";
	public final static String VERSION_MARSHMALLOW_RELEASE = "017";
	public final static String VERSION_NOUGAT_RELEASE = "029";
	public final static String VERSION_NOUGAT_MR2_PIXEL_RELEASE = "030";
	public final static String VERSION_OREO_RELEASE = "043";
	public final static String VERSION_OREO_DR1_RELEASE = "044";
	public final static String VERSION_OREO_MR1_RELEASE = "046";
	public final static String VERSION_PIE_RELEASE = "056";
	public final static String VERSION_10_RELEASE = "074";//Q
	public final static String VERSION_11_RELEASE = "085";//R

	//	"005",// kitkat-release
	//	"009",// lollipop-release
	//	"012",// lollipop-mr1-wfc-release
	//	"017",// marshmallow-release
	//	"029",// nougat-release
	//	"030",// nougat-mr2-pixel-release
	//	"043",// oreo-release
	//	"044",// taimen-op1
	//	"046",// oreo-mr1-release
	//	"051",// 
	//	"056",// pie-release
	//	"059",// android-o-mr1-iot-release-1.0.0
	//	"060",// android-o-mr1-iot-release-1.0.1
	//	"061",// android-n-iot-release-polk-at1

	/**
	 * NOTE: only going to support RELEASE versions
	 */
	public final static String[] SUPPORTED_VERSIONS = new String[] {
		//@formatter:off
		VERSION_KITKAT_RELEASE,
		VERSION_LOLLIPOP_RELEASE, 
		VERSION_LOLLIPOP_MR1_WFC_RELEASE, 
		VERSION_MARSHMALLOW_RELEASE,
		VERSION_NOUGAT_RELEASE, 
		VERSION_NOUGAT_MR2_PIXEL_RELEASE, 
		VERSION_OREO_RELEASE,
		VERSION_OREO_DR1_RELEASE, 
		VERSION_OREO_MR1_RELEASE, 
		VERSION_PIE_RELEASE, 
		VERSION_10_RELEASE,
		VERSION_11_RELEASE,
		//@formatter:on 
	};

	public final static boolean isSupportedVersion(String version) {
		for (String supportedVersion : SUPPORTED_VERSIONS) {
			if (supportedVersion.equals(version)) {
				return true;
			}
		}
		return false;
	}

	public final static boolean isART(Program program) {
		if (program != null) {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				try {
					byte[] bytes = new byte[ArtConstants.MAGIC.length()];
					block.getBytes(block.getStart(), bytes);
					String magic = new String(bytes);
					if (ArtConstants.MAGIC.equals(magic)) {
						return true;
					}
				}
				catch (Exception e) {
					//ignore
				}
			}
		}
		return false;
	}

	public final static Address findART(Program program) {
		if (program != null) {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				try {
					byte[] bytes = new byte[ArtConstants.MAGIC.length()];
					block.getBytes(block.getStart(), bytes);
					String magic = new String(bytes);
					if (ArtConstants.MAGIC.equals(magic)) {
						return block.getStart();
					}
				}
				catch (Exception e) {
					//ignore
				}
			}
		}
		return null;
	}
}
