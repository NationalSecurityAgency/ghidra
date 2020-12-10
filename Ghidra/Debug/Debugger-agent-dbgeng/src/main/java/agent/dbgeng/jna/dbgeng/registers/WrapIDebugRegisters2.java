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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_REGISTER_DESCRIPTION;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;

public class WrapIDebugRegisters2 extends WrapIDebugRegisters implements IDebugRegisters2 {
	public static class ByReference extends WrapIDebugRegisters2 implements Structure.ByReference {
	}

	public WrapIDebugRegisters2() {
	}

	public WrapIDebugRegisters2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetDescriptionWide(ULONG Register, char[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, DEBUG_REGISTER_DESCRIPTION.ByReference Desc) {
		return _invokeHR(VTIndices2.GET_DESCRIPTION_WIDE, getPointer(), Register, NameBuffer,
			NameBufferSize, NameSize, Desc);
	}

	@Override
	public HRESULT GetIndexByNameWide(WString Name, ULONGByReference Index) {
		return _invokeHR(VTIndices2.GET_INDEX_BY_NAME_WIDE, getPointer(), Name, Index);
	}

	@Override
	public HRESULT GetNumberPseudoRegisters(ULONGByReference Number) {
		return _invokeHR(VTIndices2.GET_NUMBER_PSEUDO_REGISTERS, getPointer(), Number);
	}

	@Override
	public HRESULT GetPseudoDescription(ULONG Register, byte[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, ULONGLONGByReference TypeModule, ULONGByReference TypeId) {
		return _invokeHR(VTIndices2.GET_PSEUDO_DESCRIPTION, getPointer(), Register, NameBuffer,
			NameBufferSize, NameSize, TypeModule, TypeId);
	}

	@Override
	public HRESULT GetPseudoDescriptionWide(ULONG Register, char[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, ULONGLONGByReference TypeModule, ULONGByReference TypeId) {
		return _invokeHR(VTIndices2.GET_PSEUDO_DESCRIPTION_WIDE, getPointer(), Register, NameBuffer,
			NameBufferSize, NameSize, TypeModule, TypeId);
	}

	@Override
	public HRESULT GetPseudoIndexByName(String Name, ULONGByReference Index) {
		return _invokeHR(VTIndices2.GET_PSEUDO_INDEX_BY_NAME, getPointer(), Name, Index);
	}

	@Override
	public HRESULT GetPseudoIndexByNameWide(WString Name, ULONGByReference Index) {
		return _invokeHR(VTIndices2.GET_PSEUDO_INDEX_BY_NAME_WIDE, getPointer(), Name, Index);
	}

	@Override
	public HRESULT GetPseudoValues(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices2.GET_PSEUDO_VALUES, getPointer(), Source, Count, Indices, Start,
			Values);
	}

	@Override
	public HRESULT SetPseudoValues(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices2.SET_PSEUDO_VALUES, getPointer(), Source, Count, Indices, Start,
			Values);
	}

	@Override
	public HRESULT GetValues2(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices2.GET_VALUES2, getPointer(), Source, Count, Indices, Start,
			Values);
	}

	@Override
	public HRESULT SetValues2(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values) {
		return _invokeHR(VTIndices2.SET_VALUES2, getPointer(), Source, Count, Indices, Start,
			Values);
	}

	@Override
	public HRESULT OutputRegisters2(ULONG OutputControl, ULONG Source, ULONG Flags) {
		return _invokeHR(VTIndices2.OUTPUT_REGISTERS2, getPointer(), OutputControl, Source, Flags);
	}

	@Override
	public HRESULT GetInstructionOffset2(ULONG Source, ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices2.GET_INSTRUCTION_OFFSET2, getPointer(), Source, Offset);
	}

	@Override
	public HRESULT GetStackOffset2(ULONG Source, ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices2.GET_STACK_OFFSET2, getPointer(), Source, Offset);
	}

	@Override
	public HRESULT GetFrameOffset2(ULONG Source, ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices2.GET_FRAME_OFFSET2, getPointer(), Source, Offset);
	}
}
