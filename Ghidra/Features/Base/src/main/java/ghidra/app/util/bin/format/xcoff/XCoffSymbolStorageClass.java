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
package ghidra.app.util.bin.format.xcoff;

public final class XCoffSymbolStorageClass {

	/** beginning of the common block */
	public final static int C_BCOMM = 135;
	/** beginning of include file */
	public final static int C_BINCL = 108;
	/** beginning or end of inner block */
	public final static int C_BLOCK = 100;
	/** beginning of static block */
	public final static int C_BSTAT = 143;
	/** declaration of object (type) */
	public final static int C_DECL = 140;
	/** local member of common block */
	public final static int C_ECOML = 136;
	/** end of common block */
	public final static int C_ECOMM = 127;
	/** end of include file */
	public final static int C_EINCL = 109;
	/** alternate entry */
	public final static int C_ENTRY = 141;
	/** end of static block */
	public final static int C_ESTAT = 144;
	/** external symbol */
	public final static int C_EXT = 2;
	/** beginning or end of function */
	public final static int C_FCN = 101;
	/** source file name and compiler information */
	public final static int C_FILE = 103;
	/** function or procedure */
	public final static int C_FUN = 142;
	/** global variable */
	public final static int C_GSYM = 128;
	/** unnamed external symbol */
	public final static int C_HIDEXT = 107;
	/** comment section reference */
	public final static int C_INFO = 100;
	/** automatic variable allocated on stack */
	public final static int C_LSYM = 129;
	/** symbol table entry marked for deletion */
	public final static int C_NULL = 0;
	/** argument to subroutine allocated on stack */
	public final static int C_PSYM = 130;
	/** argument to function or procedure stored in register */
	public final static int C_RPSYM = 132;
	/** register variable */
	public final static int C_RSYM = 131;
	/** static symbol (unknown) */
	public final static int C_STAT = 3;
	/** statically allocated symbol */
	public final static int C_STSYM = 133;
	/** reserved */
	public final static int C_TCSYM = 134;
	/** weak external symbol */
	public final static int C_WEAKEXT = 111;

}
