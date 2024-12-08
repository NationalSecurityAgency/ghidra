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
 * Device Tree (DT) constants. 
 *
 */
public final class DtConstants {

	/** Device Tree (DT) Magic Value */
	public static final int DT_TABLE_MAGIC = 0xd7b7ab1e;

	/** Device Tree (DT) Magic Value Bytes */
	public static final byte[] DT_TABLE_MAGIC_BYTES =
		new byte[] { (byte) 0xd7, (byte) 0xb7, (byte) 0xab, (byte) 0x1e };

	/** Device Tree (DT) Magic Value Size */
	public static final int DT_TABLE_MAGIC_SIZE = 4;

	/** Device Tree (DT) Page Size */
	public static final int DT_TABLE_DEFAULT_PAGE_SIZE = 2048;

	/** Device Tree (DT) Default Version */
	public static final int DT_TABLE_DEFAULT_VERSION = 0;

}
