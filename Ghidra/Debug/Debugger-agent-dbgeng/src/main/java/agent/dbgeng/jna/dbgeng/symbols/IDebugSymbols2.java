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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSymbols2 extends IDebugSymbols {
	final IID IID_IDEBUG_SYMBOLS2 = new IID("3a707211-afdd-4495-ad4f-56fecdf8163f");

	enum VTIndices2 implements VTableIndex {
		GET_MODULE_VERSION_INFORMATION, //
		GET_MODULE_NAME_STRING, //
		GET_CONSTANT_NAME, //
		GET_FIELD_NAME, //
		GET_TYPE_OPTIONS, //
		ADD_TYPE_OPTIONS, //
		REMOVE_TYPE_OPTIONS, //
		SET_TYPE_OPTIONS, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetModuleNameString(ULONG Which, ULONG Index, ULONGLONG Base, byte[] Buffer,
			ULONG BufferSize, ULONGByReference NameSize);
}
