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
package agent.dbgeng.jna.dbgeng.symbols;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class WrapIDebugSymbols2 extends WrapIDebugSymbols implements IDebugSymbols2 {
	public static class ByReference extends WrapIDebugSymbols2 implements Structure.ByReference {
	}

	public WrapIDebugSymbols2() {
	}

	public WrapIDebugSymbols2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetModuleNameString(ULONG Which, ULONG Index, ULONGLONG Base, byte[] Buffer,
			ULONG BufferSize, ULONGByReference NameSize) {
		return _invokeHR(VTIndices2.GET_MODULE_NAME_STRING, getPointer(), Which, Index, Base,
			Buffer, BufferSize, NameSize);
	}
}
