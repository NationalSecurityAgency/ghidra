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
package ghidra.app.util.bin.format.elf;

public class ElfProgramHeaderConstants {

	private ElfProgramHeaderConstants() {
	}

	////////////////////////////////////////////////////////////////////////////////

	// Segment Types

	/**Unused/Undefined segment*/
	public static final int PT_NULL = 0;
	/**Loadable segment*/
	public static final int PT_LOAD = 1;
	/**Dynamic linking information (.dynamic section)*/
	public static final int PT_DYNAMIC = 2;
	/**Interpreter path name*/
	public static final int PT_INTERP = 3;
	/**Auxiliary information location*/
	public static final int PT_NOTE = 4;
	/**Unused*/
	public static final int PT_SHLIB = 5;
	/**Program header table*/
	public static final int PT_PHDR = 6;
	/**Thread-local storage segment*/
	public static final int PT_TLS = 7;

	/**GCC .eh_frame_hdr segment*/
	public static final int PT_GNU_EH_FRAME = 0x6474e550;
	/**Indicates stack executability*/
	public static final int PT_GNU_STACK = 0x6474e551;
	/**Specifies segments which may be read-only after relocation*/
	public static final int PT_GNU_RELRO = 0x6474e552;
	/**Sun Specific segment*/
	public static final int PT_SUNWBSS = 0x6ffffffa;
	/**Stack segment*/
	public static final int PT_SUNWSTACK = 0x6ffffffb;

	////////////////////////////////////////////////////////////////////////////////

	/**Segment is executable*/
	public static final int PF_X                    =      1 << 0;
	/**Segment is writable*/
	public static final int PF_W                    =      1 << 1;
	/**Segment is readable*/
	public static final int PF_R                    =      1 << 2;
	/**OS-specific*/
	public static final int PF_MASKOS               =  0x0ff00000;
	/**Processor-specific*/
	public static final int PF_MASKPROC             =  0xf0000000;

}
