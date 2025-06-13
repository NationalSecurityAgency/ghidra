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

package ghidra.app.util.bin.format.plan9aout;

public class Plan9AoutMachineType {

	// These values come from a combination of sources, including Plan 9's a.out.h and zl
	// present in kencc-cross.

	public final static int HDR_MAGIC = 0x00008000;

	public final static int M_UNKNOWN = 0;
	public final static int M_68020 = (((4*8)+0)*8)+7;	// retired
	public final static int M_386 = (((4*11)+0)*11)+7;
	public final static int M_960 = (((4*12)+0)*12)+7;	// intel (retired)
	public final static int M_SPARC = (((4*13)+0)*13)+7;
	public final static int M_MIPS1 = (((4*16)+0)*16)+7;	// MIPS 3000 BE
	public final static int M_3210 = (((4*17)+0)*17)+7;	// att dsp (retired)
	public final static int M_MIPS2 = (((4*18)+0)*18)+7;	// MIPS 4000 BE
	public final static int M_29K = (((4*19)+0)*19)+7;	// AMD 29000 (retired)
	public final static int M_ARM = (((4*20)+0)*20)+7;
	public final static int M_POWERPC = (((4*21)+0)*21)+7;
	public final static int M_SPIM2 = (((4*22)+0)*22)+7;	// MIPS 4000 LE
	public final static int M_ALPHA = (((4*23)+0)*23)+7;	// DEC Alpha (retired)
	public final static int M_SPIM1 = (((4*24)+0)*24)+7;	// MIPS 3000 LE
	public final static int M_SPARC64 = (((4*25)+0)*25)+7;	// sparc64
	public final static int M_AMD64 = HDR_MAGIC | (((4*26)+0)*26)+7;
	public final static int M_POWERPC64 = HDR_MAGIC | (((4*27)+0)*27)+7;
	public final static int M_AARCH64 = HDR_MAGIC | (((4*28)+0)*28)+7;  // arm64
	public final static int M_RISCV = HDR_MAGIC | (((4*29)+0)*29)+7;	// riscv32

	final static int _magic(int f, int b) {
		return f|((((4*b)+0)*b)+7);
	}
}
