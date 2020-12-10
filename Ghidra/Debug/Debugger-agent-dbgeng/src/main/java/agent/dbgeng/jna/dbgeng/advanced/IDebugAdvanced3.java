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
package agent.dbgeng.jna.dbgeng.advanced;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugAdvanced3 extends IDebugAdvanced2 {
	final IID IID_IDEBUG_ADVANCED3 = new IID("cba4abb4-84c4-444d-87ca-a04e13286739");

	enum VTIndices3 implements VTableIndex {
		GET_SOURCE_FILE_INFORMATION_WIDE, //
		FIND_SOURCE_FILE_AND_TOKEN_WIDE, //
		GET_SYMBOL_INFORMATION_WIDE, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetSourceFileInformationWide(ULONG Which, WString SourceFile, ULONGLONG Arg64,
			ULONG Arg32, Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize);

	HRESULT FindSourceFileAndTokenWide(ULONG StartElement, ULONGLONG ModAddr, String File,
			ULONG Flags, Pointer FileToken, ULONG FileTokenSize, ULONGByReference FoundElement,
			char[] Buffer, ULONG BufferSize, ULONGByReference FoundSize);

	HRESULT GetSymbolInformationWide(ULONG Which, ULONGLONG Arg64, ULONG Arg32, Pointer Buffer,
			ULONG BufferSize, ULONGByReference InfoSize, char[] StringBuffer,
			ULONG StringBufferSize, ULONGByReference StringSize);
}
