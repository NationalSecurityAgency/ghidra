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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_REGISTER_DESCRIPTION;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugRegisters2 extends IDebugRegisters {
	final IID IID_IDEBUG_REGISTERS2 = new IID("1656afa9-19c6-4e3a-97e7-5dc9160cf9c4");

	enum VTIndices2 implements VTableIndex {
		GET_DESCRIPTION_WIDE, //
		GET_INDEX_BY_NAME_WIDE, //
		GET_NUMBER_PSEUDO_REGISTERS, //
		GET_PSEUDO_DESCRIPTION, //
		GET_PSEUDO_DESCRIPTION_WIDE, //
		GET_PSEUDO_INDEX_BY_NAME, //
		GET_PSEUDO_INDEX_BY_NAME_WIDE, //
		GET_PSEUDO_VALUES, //
		SET_PSEUDO_VALUES, //
		GET_VALUES2, //
		SET_VALUES2, //
		OUTPUT_REGISTERS2, //
		GET_INSTRUCTION_OFFSET2, //
		GET_STACK_OFFSET2, //
		GET_FRAME_OFFSET2, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetDescriptionWide(ULONG Register, char[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, DEBUG_REGISTER_DESCRIPTION.ByReference Desc);

	HRESULT GetIndexByNameWide(WString Name, ULONGByReference Index);

	HRESULT GetNumberPseudoRegisters(ULONGByReference Number);

	HRESULT GetPseudoDescription(ULONG Register, byte[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, ULONGLONGByReference TypeModule, ULONGByReference TypeId);

	HRESULT GetPseudoDescriptionWide(ULONG Register, char[] NameBuffer, ULONG NameBufferSize,
			ULONGByReference NameSize, ULONGLONGByReference TypeModule, ULONGByReference TypeId);

	HRESULT GetPseudoIndexByName(String Name, ULONGByReference Index);

	HRESULT GetPseudoIndexByNameWide(WString Name, ULONGByReference Index);

	HRESULT GetPseudoValues(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values);

	HRESULT SetPseudoValues(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values);

	HRESULT GetValues2(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values);

	HRESULT SetValues2(ULONG Source, ULONG Count, ULONG[] Indices, ULONG Start,
			DEBUG_VALUE[] Values);

	HRESULT OutputRegisters2(ULONG OutputControl, ULONG Source, ULONG Flags);

	HRESULT GetInstructionOffset2(ULONG Source, ULONGLONGByReference Offset);

	HRESULT GetStackOffset2(ULONG Source, ULONGLONGByReference Offset);

	HRESULT GetFrameOffset2(ULONG Source, ULONGLONGByReference Offset);
}
