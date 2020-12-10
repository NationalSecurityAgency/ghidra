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
package agent.dbgmodel.impl.dbgmodel.debughost;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.debughost.DebugHostType2;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostType2;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostType2;

public class DebugHostTypeImpl2 extends DebugHostTypeImpl1 implements DebugHostType2 {
	private final IDebugHostType2 jnaData;

	public DebugHostTypeImpl2(IDebugHostType2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public boolean isTypedef() {
		BOOLByReference bIsTypedef = new BOOLByReference();
		COMUtils.checkRC(jnaData.IsTypedef(bIsTypedef));
		return bIsTypedef.getValue().booleanValue();
	}

	@Override
	public DebugHostType2 getTypedefBaseType() {
		PointerByReference ppBaseType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetTypedefBaseType(ppBaseType));

		WrapIDebugHostType2 wrap = new WrapIDebugHostType2(ppBaseType.getValue());
		try {
			return (DebugHostType2) DebugHostTypeInternal.tryPreferredInterfaces(
				wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostType2 getTypedefFinalBaseType() {
		PointerByReference ppFinalBaseType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetTypedefFinalBaseType(ppFinalBaseType));

		WrapIDebugHostType2 wrap = new WrapIDebugHostType2(ppFinalBaseType.getValue());
		try {
			return (DebugHostType2) DebugHostTypeInternal.tryPreferredInterfaces(
				wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public int getFunctionVarArgsKind() {
		ULONGByReference pulVarArgsKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetFunctionVarArgsKind(pulVarArgsKind));
		return pulVarArgsKind.getValue().intValue();
	}

	@Override
	public DebugHostType2 getFunctionInstancePointerType() {
		PointerByReference ppInstancePointerType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetFunctionInstancePointerType(ppInstancePointerType));

		WrapIDebugHostType2 wrap = new WrapIDebugHostType2(ppInstancePointerType.getValue());
		try {
			return (DebugHostType2) DebugHostTypeInternal.tryPreferredInterfaces(
				wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

}
