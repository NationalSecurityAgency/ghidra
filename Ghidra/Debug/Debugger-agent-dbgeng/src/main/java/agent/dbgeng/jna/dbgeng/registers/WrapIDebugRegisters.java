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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_REGISTER_DESCRIPTION;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;

public class WrapIDebugRegisters extends UnknownWithUtils implements IDebugRegisters {
	public static class ByReference extends WrapIDebugRegisters implements Structure.ByReference {
	}

	public WrapIDebugRegisters() {
	}

	public WrapIDebugRegisters(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetNumberRegisters(ULONGByReference Number) {
		return _invokeHR(VTIndices.GET_NUMBER_REGISTERS, getPointer(), Number);
	}

	@Override
	public HRESULT GetDescription(ULONG Register, byte[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, DEBUG_REGISTER_DESCRIPTION.ByReference Desc) {
		return _invokeHR(VTIndices.GET_DESCRIPTION, getPointer(), Register, NameBuffer,
			NameBufferSize, NameSize, Desc);
	}

	@Override
	public HRESULT GetIndexByName(String Name, ULONGByReference Index) {
		return _invokeHR(VTIndices.GET_INDEX_BY_NAME, getPointer(), Name, Index);
	}

	@Override
	public HRESULT GetValue(ULONG Register, DEBUG_VALUE.ByReference Value) {
		return _invokeHR(VTIndices.GET_VALUE, getPointer(), Register, Value);
	}

	@Override
	public HRESULT SetValue(ULONG Register, DEBUG_VALUE.ByReference Value) {
		return _invokeHR(VTIndices.SET_VALUE, getPointer(), Register, Value);
	}

	@Override
	public HRESULT GetValues(ULONG Count, ULONG[] Indices, ULONG Start, DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices.GET_VALUES, getPointer(), Count, Indices, Start, Values);
	}

	@Override
	public HRESULT SetValues(ULONG Count, ULONG[] Indices, ULONG Start, DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices.SET_VALUES, getPointer(), Count, Indices, Start, Values);
	}

	@Override
	public HRESULT OutputRegisters(ULONG OutputControl, ULONG Flags) {
		return _invokeHR(VTIndices.OUTPUT_REGISTERS, getPointer(), OutputControl, Flags);
	}

	@Override
	public HRESULT GetInstructionOffset(ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices.GET_INSTRUCTION_OFFSET, getPointer(), Offset);
	}

	@Override
	public HRESULT GetStackOffset(ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices.GET_STACK_OFFSET, getPointer(), Offset);
	}

	@Override
	public HRESULT GetFrameOffset(ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices.GET_FRAME_OFFSET, getPointer(), Offset);
	}
}
