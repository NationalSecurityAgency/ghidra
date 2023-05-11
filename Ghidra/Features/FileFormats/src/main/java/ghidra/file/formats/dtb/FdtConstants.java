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
package ghidra.file.formats.dtb;

/**
 * Flattened Device Tree (FDT) constants. 
 * 
 * @see <a href="https://android.googlesource.com/platform/system/libufdt/+/refs/heads/master/utils/">libufdt utils folder</a>
 */
public final class FdtConstants {

	/** FDT Magic Value */
	public static final int FDT_MAGIC = 0xd00dfeed;

	/** FDT Magic Value Bytes */
	public static final byte[] FDT_MAGIC_BYTES =
		new byte[] { (byte) 0xd0, (byte) 0x0d, (byte) 0xfe, (byte) 0xed };

	/** FDT Magic Size */
	public static final int FDT_MAGIC_SIZE = 4;

	/** FDT TAG Size */
	public static final int FDT_TAGSIZE = 4;

	/** FDT Begin Node Value */
	public static final int FDT_BEGIN_NODE = 0x1;
	/** FDT End Node Value */
	public static final int FDT_END_NODE = 0x2;
	/** FDT Property Value */
	public static final int FDT_PROP = 0x3;
	/** FDT Begin NOP Value */
	public static final int FDT_NOP = 0x4;
	/** FDT End Node Value */
	public static final int FDT_END = 0x9;

	/** Size of FDT Header Version 1 */
	public static final int FDT_V1_SIZE = (7 * 4);
	/** Size of FDT Header Version 2 */
	public static final int FDT_V2_SIZE = (FDT_V1_SIZE + 4);
	/** Size of FDTHeader  Version 3 */
	public static final int FDT_V3_SIZE = (FDT_V2_SIZE + 4);
	/** Size of FDT Header Version 16 */
	public static final int FDT_V16_SIZE = FDT_V3_SIZE;
	/** Size of FDT Header Version 17 */
	public static final int FDT_V17_SIZE = (FDT_V16_SIZE + 4);

	/** FDT Header Version 1 */
	public static final int FDT_VERSION_1 = 1;
	/** FDT Header Version 2 */
	public static final int FDT_VERSION_2 = 2;
	/** FDT Header Version 3 */
	public static final int FDT_VERSION_3 = 3;
	/** FDT Header Version 16 */
	public static final int FDT_VERSION_16 = 16;
	/** FDT Header Version 17 */
	public static final int FDT_VERSION_17 = 17;

}
