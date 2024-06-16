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
package agent.dbgeng.impl.dbgeng.sysobj;

import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.dbgeng.COMUtilsExtra;
import agent.dbgeng.jna.dbgeng.sysobj.IDebugSystemObjects2;

public class DebugSystemObjectsImpl2 extends DebugSystemObjectsImpl1 {
	@SuppressWarnings("unused")
	private final IDebugSystemObjects2 jnaSysobj;

	public DebugSystemObjectsImpl2(IDebugSystemObjects2 jnaSysobj) {
		super(jnaSysobj);
		this.jnaSysobj = jnaSysobj;
	}
	
	public long getImplicitThreadDataOffset() {
		ULONGLONGByReference pulSysOffset = new ULONGLONGByReference();
		HRESULT hr = jnaSysobj.GetImplicitThreadDataOffset(pulSysOffset);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulSysOffset.getValue().longValue();
	}

	@Override
	public long getImplicitProcessDataOffset() {
		ULONGLONGByReference pulSysOffset = new ULONGLONGByReference();
		HRESULT hr = jnaSysobj.GetImplicitProcessDataOffset(pulSysOffset);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulSysOffset.getValue().longValue();
	}

	public void setImplicitThreadDataOffset(long offset) {
		ULONGLONG ulSysOffset = new ULONGLONG(offset);
		HRESULT hr = jnaSysobj.SetImplicitThreadDataOffset(ulSysOffset);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return;
		}
		COMUtils.checkRC(hr);
	}

	@Override
	public void setImplicitProcessDataOffset(long offset) {
		ULONGLONG ulSysOffset = new ULONGLONG(offset);
		HRESULT hr = jnaSysobj.SetImplicitProcessDataOffset(ulSysOffset);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return;
		}
		COMUtils.checkRC(hr);
	}

}
