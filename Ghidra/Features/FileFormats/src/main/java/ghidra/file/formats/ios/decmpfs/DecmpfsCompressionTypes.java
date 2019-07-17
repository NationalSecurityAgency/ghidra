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

public final class DecmpfsCompressionTypes {

	/** Uncompressed data in xattr. */
	public final static int CMP_Type1   = 1;

	/** Data stored in-line. */
	public final static int CMP_Type3   = 3;

	/** Resource fork contains compressed data. */
	public final static int CMP_Type4   = 4;

	/** ???? */
	public final static int CMP_Type10  = 10;

	public final static int CMP_MAX     = 255;

}
