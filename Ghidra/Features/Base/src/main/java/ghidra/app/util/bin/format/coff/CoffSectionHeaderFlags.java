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
package ghidra.app.util.bin.format.coff;

public final class CoffSectionHeaderFlags {
	/** Regular segment. */
	public final static long STYP_REG       = 0x0000;
	/** Dummy section. */
	public final static long STYP_DSECT     = 0x0001;
	/** No-load segment. */
	public final static long STYP_NOLOAD    = 0x0002;
	/** Group segment. */
	public final static long STYP_GROUP     = 0x0004;
	/** Pad segment. */
	public final static long STYP_PAD       = 0x0008;
	/** Copy segment. */
	public final static long STYP_COPY      = 0x0010;
	/** The section contains only executable code. */
	public final static long STYP_TEXT      = 0x0020;
	/** The section contains only initialized data. */
	public final static long STYP_DATA      = 0x0040;
	/** The section defines uninitialized data. */
	public final static long STYP_BSS       = 0x0080;
	/** Exception section */
	public final static long STYP_EXCEPT    = 0x0100;
	/** Comment section */
	public final static long STYP_INFO      = 0x0200;
	/** Overlay section (defines a piece of another named section which has no bytes) */
	public final static long STYP_OVER      = 0x0400;
	/** Library section */
	public final static long STYP_LIB       = 0x0800;
	/** Loader section */
	public final static long STYP_LOADER    = 0x1000;
	/** Debug section */
	public final static long STYP_DEBUG     = 0x2000;
	/** Type check section */
	public final static long STYP_TYPECHK   = 0x4000;
	/** RLD and line number overflow sec hdr section */
	public final static long STYP_OVRFLO    = 0x8000;
}
