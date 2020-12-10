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
package agent.dbgeng.jna.dbgeng.registers;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_REGISTER_DESCRIPTION;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

import com.sun.jna.platform.win32.COM.IUnknown;

public interface IDebugRegisters extends IUnknown {
	final IID IID_IDEBUG_REGISTERS = new IID("ce289126-9e84-45a7-937e-67bb18691493");

	enum VTIndices implements VTableIndex {
		GET_NUMBER_REGISTERS, //
		GET_DESCRIPTION, //
		GET_INDEX_BY_NAME, //
		GET_VALUE, //
		SET_VALUE, //
		GET_VALUES, //
		SET_VALUES, //
		OUTPUT_REGISTERS, //
		GET_INSTRUCTION_OFFSET, //
		GET_STACK_OFFSET, //
		GET_FRAME_OFFSET, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetNumberRegisters(ULONGByReference Number);

	HRESULT GetDescription(ULONG Register, byte[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, DEBUG_REGISTER_DESCRIPTION.ByReference Desc);

	HRESULT GetIndexByName(String Name, ULONGByReference Index);

	HRESULT GetValue(ULONG Register, DEBUG_VALUE.ByReference Value);

	HRESULT SetValue(ULONG Register, DEBUG_VALUE.ByReference Value);

	HRESULT GetValues(ULONG Count, ULONG[] Indices, ULONG Start, DEBUG_VALUE[] Values);

	HRESULT SetValues(ULONG Count, ULONG[] Indices, ULONG Start, DEBUG_VALUE[] Values);

	HRESULT OutputRegisters(ULONG OutputControl, ULONG Flags);

	HRESULT GetInstructionOffset(ULONGLONGByReference Offset);

	HRESULT GetStackOffset(ULONGLONGByReference Offset);

	HRESULT GetFrameOffset(ULONGLONGByReference Offset);
}
