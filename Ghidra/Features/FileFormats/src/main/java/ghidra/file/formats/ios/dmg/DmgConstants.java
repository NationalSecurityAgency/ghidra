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
package ghidra.file.formats.ios.dmg;

public final class DmgConstants {

	public final static byte [] DMG_MAGIC_BYTES_v1 = { 'c', 'd', 's', 'a', 'e', 'n', 'c', 'r' };

	public final static byte [] DMG_MAGIC_BYTES_v2 = { 'e', 'n', 'c', 'r', 'c', 'd', 's', 'a' };

	public final static int DMG_MAGIC_LENGTH = 8;


}
