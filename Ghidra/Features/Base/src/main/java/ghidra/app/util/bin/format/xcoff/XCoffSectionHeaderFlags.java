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
package ghidra.app.util.bin.format.xcoff;

public final class XCoffSectionHeaderFlags {
	public final static int STYP_PAD = 0x0008;
	public final static int STYP_TEXT = 0x0020;
	public final static int STYP_DATA = 0x0040;
	public final static int STYP_BSS = 0x0080;
	public final static int STYP_EXCEPT = 0x0080;
	public final static int STYP_INFO = 0x0200;
	public final static int STYP_LOADER = 0x1000;
	public final static int STYP_DEBUG = 0x2000;
	public final static int STYP_TYPCHK = 0x4000;
	public final static int STYP_OVRFLO = 0x8000;
}
