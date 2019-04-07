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
package ghidra.file.formats.lzss;

public final class LzssConstants {

	public final static int     SIGNATURE_COMPRESSION       = 0x636f6d70;
	public final static byte [] SIGNATURE_COMPRESSION_BYTES = { 'c', 'o', 'm', 'p' };

	public final static int     SIGNATURE_LZSS              = 0x6c7a7373;
	public final static byte [] SIGNATURE_LZSS_BYTES        = { 'l', 'z', 's', 's' };

	public final static int     PADDING_LENGTH              = 0x16c;

	public final static int     HEADER_LENGTH               = 4 + 4 + 4 + 4 + 4 + PADDING_LENGTH;
}
