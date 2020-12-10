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
package agent.dbgeng.impl.dbgeng.io;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.DebugOutputCallbacks;
import agent.dbgeng.jna.dbgeng.io.*;

public class WrapCallbackIDebugOutputCallbacksWide implements CallbackIDebugOutputCallbacksWide {
	private final DebugOutputCallbacks cb;
	private ListenerIDebugOutputCallbacksWide listener;

	public WrapCallbackIDebugOutputCallbacksWide(DebugOutputCallbacks cb) {
		this.cb = cb;
	}

	public void setListener(ListenerIDebugOutputCallbacksWide listener) {
		this.listener = listener;
	}

	@Override
	public Pointer getPointer() {
		return listener.getPointer();
	}

	@Override
	public HRESULT QueryInterface(REFIID refid, PointerByReference ppvObject) {
		if (null == ppvObject) {
			return new HRESULT(WinError.E_POINTER);
		}
		else if (refid.getValue()
				.equals(IDebugOutputCallbacksWide.IID_IDEBUG_OUTPUT_CALLBACKS_WIDE)) {
			ppvObject.setValue(this.getPointer());
			return WinError.S_OK;
		}
		else if (refid.getValue().equals(IUnknown.IID_IUNKNOWN)) {
			ppvObject.setValue(this.getPointer());
			return WinError.S_OK;
		}
		return new HRESULT(WinError.E_NOINTERFACE);
	}

	@Override
	public int AddRef() {
		return 0;
	}

	@Override
	public int Release() {
		return 0;
	}

	@Override
	public HRESULT Output(ULONG Mask, WString Text) {
		try {
			cb.output(Mask.intValue(), Text.toString());
			return WinError.S_OK;
		}
		catch (Throwable e) {
			return new HRESULT(WinError.E_UNEXPECTED);
		}
	}
}
