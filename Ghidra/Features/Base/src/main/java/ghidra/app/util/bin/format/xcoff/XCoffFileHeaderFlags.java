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

public final class XCoffFileHeaderFlags {

	/** relocation info stripped from file */
	public final static int F_RELFLG       = 0x0001;
	/** file is executable (no unresolved external references) */
	public final static int F_EXEC         = 0x0002;
	/** line numbers stripped from file */
	public final static int F_LNNO         = 0x0004;
	/** local symbols stripped from file */
	public final static int F_LSYMS        = 0x0008;
	/** file was profiled with fdpr command */
	public final static int F_FDPR_PROF    = 0x0010;
	/** file was reordered with fdpr command */
	public final static int F_FDPR_OPTI    = 0x0020;
	/** file uses Very Large Program Support */
	public final static int F_DSA          = 0x0040;
	/** file is 16-bit little-endian */
	public final static int F_AR16WR       = 0x0080;
	/** file is 32-bit little-endian */
	public final static int F_AR32WR       = 0x0100;
	/** file is 32-bit big-endian */
	public final static int F_AR32W        = 0x0200;
	/** rs/6000 aix: dynamically loadable w/imports and exports */
	public final static int F_DYNLOAD      = 0x1000;
	/** rs/6000 aix: file is a shared object */
	public final static int F_SHROBJ       = 0x2000;
	/**
	 * rs/6000 aix: if the object file is a member of an archive
	 * it can be loaded by the system loader but the member is ignored by the binder.
	 */
	public final static int F_LOADONLY     = 0x4000;

	public final static boolean isStrip(XCoffFileHeader header) {
		return (header.getFlags() & F_RELFLG) == F_RELFLG;
	}

	public final static boolean isExec(XCoffFileHeader header) {
		return (header.getFlags() & F_EXEC) == F_EXEC;
	}

	public final static boolean isDebug(XCoffFileHeader header) {
		return !((header.getFlags() & F_LNNO) == F_LNNO);
	}
}
