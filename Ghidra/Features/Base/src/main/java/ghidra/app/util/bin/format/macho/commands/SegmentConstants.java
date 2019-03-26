/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macho.commands;

public final class SegmentConstants {

	/** Read protection flag. */
	public final static int PROTECTION_R = 0x1;
	/** Write protection flag. */
	public final static int PROTECTION_W = 0x2;
	/** Execute protection flag. */
	public final static int PROTECTION_X = 0x4;

	/** If this flag bit is set, the segment contains Apple protection. */
	public final static int FLAG_APPLE_PROTECTED = 0x8;

}
