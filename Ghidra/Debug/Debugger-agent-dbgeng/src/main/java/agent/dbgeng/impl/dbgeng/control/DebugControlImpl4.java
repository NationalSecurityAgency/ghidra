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
package agent.dbgeng.impl.dbgeng.control;

import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.COMUtilsExtra;
import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugValue.DebugValueType;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.breakpoint.DebugBreakpointInternal;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.control.IDebugControl4;
import ghidra.comm.util.BitmaskSet;

public class DebugControlImpl4 extends DebugControlImpl3 {
	private final IDebugControl4 jnaControl;

	public DebugControlImpl4(IDebugControl4 jnaControl) {
		super(jnaControl);
		this.jnaControl = jnaControl;
	}

	@Override
	public void print(BitmaskSet<DebugOutputLevel> levels, String message) {
		ULONG mask = new ULONG(levels.getBitmask());
		COMUtils.checkRC(jnaControl.OutputWide(mask, new WString("%s"), new WString(message)));
	}

	@Override
	public void println(BitmaskSet<DebugOutputLevel> levels, String message) {
		ULONG mask = new ULONG(levels.getBitmask());
		COMUtils
				.checkRC(
					jnaControl.OutputWide(mask, new WString("%s"), new WString(message + "\r\n")));
	}

	@Override
	public void prompt(BitmaskSet<DebugOutputControl> ctl, String message) {
		ULONG ctlMask = new ULONG(ctl.getBitmask());
		COMUtils
				.checkRC(
					jnaControl.OutputPromptWide(ctlMask, new WString("%s"), new WString(message)));
	}

	@Override
	public String getPromptText() {
		ULONGByReference pulTextSize = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetPromptTextWide(null, new ULONG(0), pulTextSize));
		char[] buffer = new char[pulTextSize.getValue().intValue()];
		COMUtils.checkRC(jnaControl.GetPromptTextWide(buffer, pulTextSize.getValue(), null));
		return Native.toString(buffer);
	}

	@Override
	protected DEBUG_VALUE doEval(DebugValueType type, String expression) {
		DEBUG_VALUE.ByReference value = new DEBUG_VALUE.ByReference();
		ULONGByReference pulRemainder = new ULONGByReference();
		COMUtils.checkRC(jnaControl.EvaluateWide(new WString(expression), new ULONG(type.ordinal()),
			value, pulRemainder));
		int remainder = pulRemainder.getValue().intValue();
		if (remainder != expression.length()) {
			throw new RuntimeException("Failed to parse: " + expression.substring(remainder));
		}
		return value;
	}

	@Override
	public void execute(BitmaskSet<DebugOutputControl> ctl, String cmd,
			BitmaskSet<DebugExecute> flags) {
		ULONG ctlMask = new ULONG(ctl.getBitmask());
		ULONG flagMask = new ULONG(flags.getBitmask());
		HRESULT hr = jnaControl.ExecuteWide(ctlMask, new WString(cmd), flagMask);
		if (hr.equals(COMUtilsExtra.E_INTERNALEXCEPTION)) {
			return;
		}
		COMUtils.checkRC(hr);
	}

	@Override
	public void returnInput(String input) {
		COMUtils.checkRC(jnaControl.ReturnInputWide(new WString(input)));
	}

	public DebugBreakpoint doAddBreakpoint2(BreakType type, ULONG ulDesiredId) {
		ULONG ulType = new ULONG(type.ordinal());
		PointerByReference ppBp = new PointerByReference();
		COMUtils.checkRC(jnaControl.AddBreakpoint2(ulType, ulDesiredId, ppBp));
		IDebugBreakpoint Bp = new WrapIDebugBreakpoint(ppBp.getValue());
		DebugBreakpoint bpt =
			DebugBreakpointInternal.tryPreferredInterfaces(this, Bp::QueryInterface);
		// AddRef or no? Probably not.
		return bpt;
	}

	@Override
	public DebugBreakpoint addBreakpoint2(BreakType type, int desiredId) {
		return doAddBreakpoint2(type, new ULONG(desiredId));
	}

	@Override
	public DebugBreakpoint addBreakpoint2(BreakType type) {
		return doAddBreakpoint2(type, DbgEngUtil.DEBUG_ANY_ID);
	}

}
