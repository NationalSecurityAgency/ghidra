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
package ghidra.app.util.bin.format.coff;

public final class CoffFileHeaderFlag {

	/**
	 * If set, there is not relocation information
	 * in this file. This is usually clear for objects
	 * and set for executables.
	 */
	public final static int F_RELFLG  = 0x0001;

	/**
	 * If set, all unresolved symbols have been resolved 
	 * and the file may be considered executable.
	 */
	public final static int F_EXEC    = 0x0002;

	/**
	 * If set, all line number information has been removed
	 * from the file (or was never added in the first place).
	 */
	public final static int F_LNNO    = 0x0004;

	/**
	 * If set, all local symbols have been removed from 
	 * the file (or were never added in the first place).
	 */
	public final static int F_LSYMS   = 0x0008;

	/**
	 * Indicates this file is a minimal object file (".m")
	 */
	public final static int F_MINMAL  = 0x0010;

	/**
	 * Indicates this file is a fully bound update
	 * file.
	 */
	public final static int F_UPDATE  = 0x0020;

	/**
	 * Indicates this file has had its bytes
	 * swabbed (in names).
	 */
	public final static int F_SWABD   = 0x0040;

	public final static int F_AR16WR  = 0x0080;

	/**
	 * Indicates that the file is 32-bit little endian.
	 */
	public final static int F_AR32WR  = 0x0100;

	public final static int F_AR32W   = 0x0200;

	public final static int F_PATCH   = 0x0400;

	public final static int F_NODF    = 0x0400;

}
