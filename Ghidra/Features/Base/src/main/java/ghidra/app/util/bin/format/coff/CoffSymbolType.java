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

public final class CoffSymbolType {

	public final static int T_NULL          = 0x0000;
	public final static int T_VOID          = 0x0001; // void function argument
	public final static int T_CHAR          = 0x0002;
	public final static int T_SHORT         = 0x0003;
	public final static int T_INT           = 0x0004;
	public final static int T_LONG          = 0x0005;
	public final static int T_FLOAT         = 0x0006;
	public final static int T_DOUBLE        = 0x0007;
	public final static int T_STRUCT        = 0x0008;
	public final static int T_UNION         = 0x0009;
	public final static int T_ENUM          = 0x000a;
	public final static int T_MOE           = 0x000b; // member of enumeration
	public final static int T_UCHAR         = 0x000c;
	public final static int T_USHORT        = 0x000d;
	public final static int T_UINT          = 0x000e;
	public final static int T_ULONG         = 0x000f;
	public final static int T_LONG_DOUBLE   = 0x0010;

	public final static int DT_NON          = 0x0000; // no derived T
	public final static int DT_PTR          = 0x0001; // pointer to T
	public final static int DT_FCN          = 0x0002; // function returning T
	public final static int DT_ARY          = 0x0003; // array of T

	public final static int getBaseType(int symbolType) {
		return symbolType & 0xf;
	}

	public final static int getDerivedType(int symbolType) {
		return symbolType & 0xf0;
	}
}
