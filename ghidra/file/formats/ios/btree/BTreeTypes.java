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
package ghidra.file.formats.ios.btree;

public final class BTreeTypes {

	/** Control file */
	public final static byte kHFSBTreeType       =  (byte)0;
	/** User bTree types start from 128 */
	public final static byte kUserBTreeType      =  (byte)128;
	/** */
	public final static byte kReservedBTreeType  =  (byte)255;
}
