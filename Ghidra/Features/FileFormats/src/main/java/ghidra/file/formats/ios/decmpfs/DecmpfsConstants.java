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
package ghidra.file.formats.ios.decmpfs;

public final class DecmpfsConstants {

	public final static int MAX_DECMPFS_XATTR_SIZE  =  3802;

	public final static byte [] DECMPFS_MAGIC_BYTES  =  { 'f', 'p', 'm', 'c' };
	public final static String  DECMPFS_MAGIC        =  new String( DECMPFS_MAGIC_BYTES );
	
}
