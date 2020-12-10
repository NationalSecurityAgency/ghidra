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
package agent.dbgmodel.jna.dbgmodel.datamodel.script.debug;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelScriptDebugStackFrame extends UnknownWithUtils
		implements IDataModelScriptDebugStackFrame {
	public static class ByReference extends WrapIDataModelScriptDebugStackFrame
			implements Structure.ByReference {
	}

	public WrapIDataModelScriptDebugStackFrame() {
	}

	public WrapIDataModelScriptDebugStackFrame(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetName(BSTRByReference name) {
		return _invokeHR(VTIndices.GET_NAME, getPointer(), name);
	}

	@Override
	public HRESULT GetPosition(Pointer position, Pointer positionSpanEnd,
			BSTRByReference lineText) {
		return _invokeHR(VTIndices.GET_POSITION, getPointer(), position, positionSpanEnd, lineText);
	}

	@Override
	public HRESULT IsTransitionPoint(BOOLByReference isTransitionPoint) {
		return _invokeHR(VTIndices.IS_TRANSITION_POINT, getPointer(), isTransitionPoint);
	}

	@Override
	public HRESULT GetTransition(PointerByReference transitionScript,
			BOOLByReference isTransitionContiguous) {
		return _invokeHR(VTIndices.GET_TRANSITION, getPointer(), transitionScript,
			isTransitionContiguous);
	}

	@Override
	public HRESULT Evaluate(WString pwszExpression, PointerByReference ppResult) {
		return _invokeHR(VTIndices.EVALUATE, getPointer(), pwszExpression, ppResult);
	}

	@Override
	public HRESULT EnumerateLocals(PointerByReference variablesEnum) {
		return _invokeHR(VTIndices.ENUMERATE_LOCALS, getPointer(), variablesEnum);
	}

	@Override
	public HRESULT EnumerateArguments(PointerByReference variablesEnum) {
		return _invokeHR(VTIndices.ENUMERATE_ARGUMENTS, getPointer(), variablesEnum);
	}

}
