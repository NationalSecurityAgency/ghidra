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
package ghidra.file.formats.ios.ibootim;

public final class iBootImConstants {

	public final static String  SIGNATURE            =  "iBootIm";
	public final static byte [] SIGNATURE_BYTES      =  { 'i', 'B', 'o', 'o', 't', 'I', 'm', '\0' };
	public final static int     SIGNATURE_LENGTH     =  0x8;

	public final static int     PADDING_LENGTH       =  0x28;

	public final static int     COMPRESSION_LZSS_BE  =  0x6c7a7373;
	public final static int     COMPRESSION_LZSS_LE  =  0x73737a6c;
  
	public final static int     FORMAT_ARGB          =  0x61726762;
	public final static int     FORMAT_GREY          =  0x67726579;

	public final static int     HEADER_LENGTH        =  SIGNATURE_LENGTH + 4 + 4 + 4 + 2 + 2 + PADDING_LENGTH;
}
