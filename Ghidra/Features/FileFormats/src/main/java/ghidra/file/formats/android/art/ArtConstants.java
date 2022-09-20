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
 * <a href="https://android.googlesource.com/platform/art/+/master/runtime/image.cc">master/runtime/image.cc</a>
 */
public final class ArtConstants {

	public final static String ART_NAME = "Android Runtime (ART)";

	public final static String MAGIC = "art\n";

	public final static int VERSION_LENGTH = 4;

	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/image.cc#26">kitkat-release/runtime/image.c</a> */
	public final static String ART_VERSION_005 = "005";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/image.cc#26">lollipop-release/runtime/image.c</a>  */
	public final static String ART_VERSION_009 = "009";
	/** <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-wfc-release/runtime/image.cc#26">lollipop-mr1-wfc-release/runtime/image.c</a> */
	public final static String ART_VERSION_012 = "012";
	/** <a href="https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/image.cc#26">marshmallow-release/runtime/image.c</a> */
	public final static String ART_VERSION_017 = "017";
	/** <a href="https://android.googlesource.com/platform/art/+/nougat-release/runtime/image.cc#26">nougat-release/runtime/image.c</a> */
	public final static String ART_VERSION_029 = "029";
	/** <a href="https://android.googlesource.com/platform/art/+/nougat-mr2-pixel-release/runtime/image.cc#26">nougat-mr2-pixel-release/runtime/image.c</a> */
	public final static String ART_VERSION_030 = "030";
	/** <a href="https://android.googlesource.com/platform/art/+/oreo-release/runtime/image.cc#28">oreo-release/runtime/image.c</a> */
	public final static String ART_VERSION_043 = "043";
	/** <a href="https://android.googlesource.com/platform/art/+/oreo-dr1-release/runtime/image.cc#28">oreo-dr1-release/runtime/image.c</a> */
	public final static String ART_VERSION_044 = "044";
	/** <a href="https://android.googlesource.com/platform/art/+/oreo-mr1-release/runtime/image.cc#28">oreo-mr1-release/runtime/image.c</a> */
	public final static String ART_VERSION_046 = "046";
	/** <a href="https://android.googlesource.com/platform/art/+/pie-release/runtime/image.cc#28">pie-release/runtime/image.c</a> */
	public final static String ART_VERSION_056 = "056";
	/** <a href="https://android.googlesource.com/platform/art/+/android10-release/runtime/image.cc#31">android10-release/runtime/image.c</a> */
	public final static String ART_VERSION_074 = "074";//Q
	/** <a href="https://android.googlesource.com/platform/art/+/android11-release/runtime/image.cc#31">android11-release/runtime/image.c</a> */
	public final static String ART_VERSION_085 = "085";//R
	/** <a href="https://android.googlesource.com/platform/art/+/android12-release/runtime/image.cc#31">android12-release/runtime/image.c</a> */
	public final static String ART_VERSION_099 = "099";//S
	/** <a href="https://android.googlesource.com/platform/art/+/android13-release/runtime/image.cc#31">android13-release/runtime/image.c</a> */
	public final static String ART_VERSION_106 = "106";//S v2, 13

	/**
	 * NOTE: only going to support RELEASE versions
	 */
	public final static String[] SUPPORTED_VERSIONS = new String[] {
		//@formatter:off
		ART_VERSION_005,
		ART_VERSION_009, 
		ART_VERSION_012, 
		ART_VERSION_017,
		ART_VERSION_029, 
		ART_VERSION_030, 
		ART_VERSION_043,
		ART_VERSION_044, 
		ART_VERSION_046, 
		ART_VERSION_056, 
		ART_VERSION_074,
		ART_VERSION_085,
		ART_VERSION_099,
		ART_VERSION_106,
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
