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
package ghidra.app.util.bin.format.pe;

/**
 * PE machine ID constants defined by standard header file 'ntimage.h'
 * 
 * @see <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/mt804345%28v=vs.85%29.aspx">Image File Machine Constants</a>
 */
public class MachineConstants {

	public final static short IMAGE_FILE_MACHINE_UNKNOWN           =         0x0000;
	public final static short IMAGE_FILE_MACHINE_I386              =         0x014c;// Intel 386.
	public final static short IMAGE_FILE_MACHINE_R3000             =         0x0162;// MIPS little-endian, 0x160 big-endian
	public final static short IMAGE_FILE_MACHINE_R4000             =         0x0166;// MIPS little-endian
	public final static short IMAGE_FILE_MACHINE_R10000            =         0x0168;// MIPS little-endian
	public final static short IMAGE_FILE_MACHINE_WCEMIPSV2         =         0x0169;// MIPS little-endian WCE v2
	public final static short IMAGE_FILE_MACHINE_ALPHA             =         0x0184;// Alpha_AXP
	public final static short IMAGE_FILE_MACHINE_SH3               =         0x01a2;// SH3 little-endian
	public final static short IMAGE_FILE_MACHINE_SH3DSP            =         0x01a3;
	public final static short IMAGE_FILE_MACHINE_SH3E              =         0x01a4;// SH3E little-endian
	public final static short IMAGE_FILE_MACHINE_SH4               =         0x01a6;// SH4 little-endian
	public final static short IMAGE_FILE_MACHINE_SH5               =         0x01a8;// SH5
	public final static short IMAGE_FILE_MACHINE_ARM               =         0x01c0;// ARM Little-Endian
	public final static short IMAGE_FILE_MACHINE_THUMB             =         0x01c2;// ARM Thumb/Thumb-2 Little-Endian
	public final static short IMAGE_FILE_MACHINE_ARMNT             =         0x01c4;// ARM Thumb-2 Little-Endian
	public final static short IMAGE_FILE_MACHINE_AM33              =         0x01d3;
	public final static short IMAGE_FILE_MACHINE_POWERPC           =         0x01F0;// PowerPC Little-Endian
	public final static short IMAGE_FILE_MACHINE_POWERPCFP         =         0x01f1;// PowerPC w/ Floating Point Support 
	public final static short IMAGE_FILE_MACHINE_IA64              =         0x0200;// Intel 64
	public final static short IMAGE_FILE_MACHINE_MIPS16            =         0x0266;// MIPS
	public final static short IMAGE_FILE_MACHINE_ALPHA64           =         0x0284;// ALPHA64
	public final static short IMAGE_FILE_MACHINE_MIPSFPU           =         0x0366;// MIPS
	public final static short IMAGE_FILE_MACHINE_MIPSFPU16         =         0x0466;// MIPS
	public final static short IMAGE_FILE_MACHINE_TRICORE           =         0x0520;// Infineon
	public final static short IMAGE_FILE_MACHINE_CEF               =         0x0CEF;
	public final static short IMAGE_FILE_MACHINE_EBC               =         0x0EBC;// EFI Byte Code

	public final static short IMAGE_FILE_MACHINE_AMD64             = (short) 0x8664;// AMD64 (K8)
	public final static short IMAGE_FILE_MACHINE_M32R              = (short) 0x9041;// M32R little-endian
	public final static short IMAGE_FILE_MACHINE_ARM64             = (short) 0xaa64;// ARM v8 64-bit;
	public final static short IMAGE_FILE_MACHINE_CEE               = (short) 0xC0EE;

	public final static short IMAGE_FILE_MACHINE_AXP64             =         IMAGE_FILE_MACHINE_ALPHA64;
}
