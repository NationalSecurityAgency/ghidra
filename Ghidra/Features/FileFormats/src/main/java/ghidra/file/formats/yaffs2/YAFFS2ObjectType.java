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
package ghidra.file.formats.yaffs2;

/**
 * Yaffs2 object type enum.  The java enum ordinal must match the yaffs enum values.
 */
public enum YAFFS2ObjectType {
	Unknown,        // 0
	File,           // 1
	Symlink,        // 2
	Directory,      // 3
	Hardlink,       // 4
	Special,        // 5
	INVALID;        // represents value that doesn't match, including Unknown

	public static YAFFS2ObjectType parse(long i) {
		YAFFS2ObjectType[] values = values();
		return i > Unknown.ordinal() && i < INVALID.ordinal() ? values[(int) i] : INVALID;
	}
}
