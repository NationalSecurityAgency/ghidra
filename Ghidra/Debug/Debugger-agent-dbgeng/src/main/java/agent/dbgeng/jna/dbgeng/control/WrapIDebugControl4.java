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
package agent.dbgeng.jna.dbgeng.control;

import java.util.*;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;

public class WrapIDebugControl4 extends WrapIDebugControl3 implements IDebugControl4 {
	public static class ByReference extends WrapIDebugControl4 implements Structure.ByReference {
	}

	public WrapIDebugControl4() {
	}

	public WrapIDebugControl4(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT AddBreakpoint2(ULONG Type, ULONG DesiredId, PointerByReference Bp) {
		return _invokeHR(VTIndices4.ADD_BREAKPOINT2, getPointer(), Type, DesiredId, Bp);
	}

	@Override
	public HRESULT ReturnInputWide(WString Buffer) {
		return _invokeHR(VTIndices4.RETURN_INPUT_WIDE, getPointer(), Buffer);
	}

	@Override
	public HRESULT OutputWide(ULONG Mask, WString Format, Object... objects) {
		List<Object> args = new ArrayList<>();
		args.add(getPointer());
		args.add(Format);
		args.addAll(Arrays.asList(objects));
		return _invokeHR(VTIndices4.OUTPUT_WIDE, args.toArray());
	}

	@Override
	public HRESULT OutputPromptWide(ULONG OutputControl, WString Format, Object... objects) {
		List<Object> args = new ArrayList<>();
		args.add(getPointer());
		args.add(OutputControl);
		args.add(Format);
		args.addAll(Arrays.asList(objects));
		return _invokeHR(VTIndices4.OUTPUT_PROMPT_WIDE, args.toArray());
	}

	@Override
	public HRESULT GetPromptTextWide(char[] Buffer, ULONG BufferSize, ULONGByReference TextSize) {
		return _invokeHR(VTIndices4.GET_PROMPT_TEXT_WIDE, getPointer(), Buffer, BufferSize,
			TextSize);
	}

	@Override
	public HRESULT EvaluateWide(WString Expression, ULONG DesiredType,
			DEBUG_VALUE.ByReference Value, ULONGByReference RemainderIndex) {
		return _invokeHR(VTIndices4.EVALUATE_WIDE, getPointer(), Expression, DesiredType, Value,
			RemainderIndex);
	}

	@Override
	public HRESULT ExecuteWide(ULONG OutputControl, WString Command, ULONG Flags) {
		return _invokeHR(VTIndices4.EXECUTE_WIDE, getPointer(), OutputControl, Command, Flags);
	}
}
