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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugBreakpoint2 extends IDebugBreakpoint {
	final IID IID_IDEBUG_BREAKPOINT2 = new IID("1b278d20-79f2-426e-a3f9-c1ddf375d48e");

	enum VTIndices2 implements VTableIndex {
		GET_COMMAND_WIDE, //
		SET_COMMAND_WIDE, //
		GET_OFFSET_EXPRESSION_WIDE, //
		SET_OFFSET_EXPRESSION_WIDE, //
		;

		public int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetCommandWide(char[] Buffer, ULONG BufferSize, ULONGByReference CommandSize);

	HRESULT SetComamndWide(WString Command);

	HRESULT GetOffsetExpressionWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference ExpressionSize);

	HRESULT SetOffsetExpressionWide(WString Expression);
}
