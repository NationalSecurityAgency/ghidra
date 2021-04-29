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
package agent.dbgeng.jna.dbgeng.breakpoint;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class WrapIDebugBreakpoint2 extends WrapIDebugBreakpoint implements IDebugBreakpoint2 {
	public static class ByReference extends WrapIDebugBreakpoint2 implements Structure.ByReference {
	}

	public WrapIDebugBreakpoint2() {
	}

	public WrapIDebugBreakpoint2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetCommandWide(char[] Buffer, ULONG BufferSize, ULONGByReference CommandSize) {
		return _invokeHR(VTIndices2.GET_COMMAND_WIDE, getPointer(), Buffer, BufferSize,
			CommandSize);
	}

	@Override
	public HRESULT SetComamndWide(WString Command) {
		return _invokeHR(VTIndices2.SET_COMMAND_WIDE, getPointer(), Command);
	}

	@Override
	public HRESULT GetOffsetExpressionWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference ExpressionSize) {
		return _invokeHR(VTIndices2.GET_OFFSET_EXPRESSION_WIDE, getPointer(), Buffer, BufferSize,
			ExpressionSize);
	}

	@Override
	public HRESULT SetOffsetExpressionWide(WString Expression) {
		return _invokeHR(VTIndices2.SET_OFFSET_EXPRESSION_WIDE, getPointer(), Expression);
	}
}
