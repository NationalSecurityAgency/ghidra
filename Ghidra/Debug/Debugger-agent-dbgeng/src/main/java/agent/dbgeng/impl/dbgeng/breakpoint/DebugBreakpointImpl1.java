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
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.DbgEng;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.impl.dbgeng.client.DebugClientInternal;
import agent.dbgeng.impl.dbgeng.control.DebugControlInternal;
import agent.dbgeng.jna.dbgeng.WinNTExtra.Machine;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.client.WrapIDebugClient;
import ghidra.comm.util.BitmaskSet;

public class DebugBreakpointImpl1 implements DebugBreakpointInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private IDebugBreakpoint jnaBreakpoint;
	private DebugControlInternal control;

	public DebugBreakpointImpl1(IDebugBreakpoint jnaBreakpoint) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaBreakpoint);
		this.jnaBreakpoint = jnaBreakpoint;
	}

	@Override
	public void setControl(DebugControlInternal control) {
		this.control = control;
	}

	@Override
	public void remove() {
		control.removeBreakpoint(jnaBreakpoint);
		// Prevent accidental access. Will be released during GC. NPE is better than segfault.
		jnaBreakpoint = null;
	}

	@Override
	public int getId() {
		ULONGByReference pulId = new ULONGByReference();
		COMUtils.checkRC(jnaBreakpoint.GetId(pulId));
		return pulId.getValue().intValue();
	}

	@Override
	public BreakFullType getType() {
		ULONGByReference pulBreakType = new ULONGByReference();
		ULONGByReference pulProcType = new ULONGByReference();
		COMUtils.checkRC(jnaBreakpoint.GetType(pulBreakType, pulProcType));
		BreakType breakType = BreakType.values()[pulBreakType.getValue().intValue()];
		Machine procType = Machine.getByNumber(pulProcType.getValue().intValue());
		return new BreakFullType(breakType, procType);
	}

	@Override
	public DebugClient getAdder() {
		PointerByReference pClient = new PointerByReference();
		COMUtils.checkRC(jnaBreakpoint.GetAdder(pClient.getPointer()));
		WrapIDebugClient wrap = new WrapIDebugClient(pClient.getValue());

		try {
			return DebugClientInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public BitmaskSet<BreakFlags> getFlags() {
		ULONGByReference pulFlags = new ULONGByReference();
		COMUtils.checkRC(jnaBreakpoint.GetFlags(pulFlags));
		return new BitmaskSet<>(BreakFlags.class, pulFlags.getValue().longValue());
	}

	@Override
	public void addFlags(BitmaskSet<BreakFlags> flags) {
		ULONG ulFlags = new ULONG(flags.getBitmask());
		COMUtils.checkRC(jnaBreakpoint.AddFlags(ulFlags));
	}

	@Override
	public void addFlags(BreakFlags... flags) {
		addFlags(BitmaskSet.of(flags));
	}

	@Override
	public void removeFlags(BitmaskSet<BreakFlags> flags) {
		ULONG ulFlags = new ULONG(flags.getBitmask());
		COMUtils.checkRC(jnaBreakpoint.RemoveFlags(ulFlags));
	}

	@Override
	public void removeFlags(BreakFlags... flags) {
		removeFlags(BitmaskSet.of(flags));
	}

	@Override
	public void setFlags(BitmaskSet<BreakFlags> flags) {
		ULONG ulFlags = new ULONG(flags.getBitmask());
		COMUtils.checkRC(jnaBreakpoint.SetFlags(ulFlags));
	}

	@Override
	public void setFlags(BreakFlags... flags) {
		setFlags(BitmaskSet.of(flags));
	}

	@Override
	public Long getOffset() {
		ULONGLONGByReference pullOffset = new ULONGLONGByReference();
		HRESULT getOffset = jnaBreakpoint.GetOffset(pullOffset);
		if (getOffset.longValue() == Kernel32.E_NOINTERFACE) {
			// Per MSDN, this means the placement is deferred
			return null;
		}
		COMUtils.checkRC(getOffset);
		return pullOffset.getValue().longValue();
	}

	@Override
	public void setOffset(long offset) {
		ULONGLONG ullOffset = new ULONGLONG(offset);
		COMUtils.checkRC(jnaBreakpoint.SetOffset(ullOffset));
	}

	@Override
	public String getOffsetExpression() {
		ULONGByReference pulExpressionSize = new ULONGByReference();
		COMUtils.checkRC(jnaBreakpoint.GetOffsetExpression(null, new ULONG(0), pulExpressionSize));
		byte[] buffer = new byte[pulExpressionSize.getValue().intValue()];
		COMUtils.checkRC(
			jnaBreakpoint.GetOffsetExpression(buffer, pulExpressionSize.getValue(), null));
		return Native.toString(buffer);
	}

	@Override
	public void setOffsetExpression(String expression) {
		COMUtils.checkRC(jnaBreakpoint.SetOffsetExpression(expression));
	}

	@Override
	public BreakDataParameters getDataParameters() {
		ULONGByReference pulSize = new ULONGByReference();
		ULONGByReference pulAccessType = new ULONGByReference();
		COMUtils.checkRC(jnaBreakpoint.GetDataParameters(pulSize, pulAccessType));
		return new BreakDataParameters(pulSize.getValue().intValue(),
			new BitmaskSet<>(BreakAccess.class, pulAccessType.getValue().intValue()));
	}

	@Override
	public void setDataParameters(BreakDataParameters params) {
		setDataParameters(params.size, params.access);
	}

	@Override
	public void setDataParameters(int size, BitmaskSet<BreakAccess> access) {
		ULONG ulSize = new ULONG(size);
		ULONG ulAccessType = new ULONG(access.getBitmask());
		COMUtils.checkRC(jnaBreakpoint.SetDataParameters(ulSize, ulAccessType));
	}

	@Override
	public void setDataParameters(int size, BreakAccess... access) {
		setDataParameters(size, BitmaskSet.of(access));
	}
}
