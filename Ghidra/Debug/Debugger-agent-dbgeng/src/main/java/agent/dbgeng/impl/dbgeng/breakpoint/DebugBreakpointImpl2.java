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
package agent.dbgeng.impl.dbgeng.breakpoint;

import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint2;

public class DebugBreakpointImpl2 extends DebugBreakpointImpl1 {
	@SuppressWarnings("unused")
	private final IDebugBreakpoint2 jnaBreakpoint;

	public DebugBreakpointImpl2(IDebugBreakpoint2 jnaBreakpoint) {
		super(jnaBreakpoint);
		this.jnaBreakpoint = jnaBreakpoint;
	}

	@Override
	public String getOffsetExpression() {
		ULONGByReference pulExpressionSize = new ULONGByReference();
		COMUtils.checkRC(
			jnaBreakpoint.GetOffsetExpressionWide(null, new ULONG(0), pulExpressionSize));
		char[] buffer = new char[pulExpressionSize.getValue().intValue()];
		COMUtils.checkRC(
			jnaBreakpoint.GetOffsetExpressionWide(buffer, pulExpressionSize.getValue(), null));
		return Native.toString(buffer);
	}

	@Override
	public void setOffsetExpression(String expression) {
		COMUtils.checkRC(jnaBreakpoint.SetOffsetExpressionWide(new WString(expression)));
	}
}
