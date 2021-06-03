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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHostEvaluator1 extends UnknownWithUtils implements IDebugHostEvaluator1 {
	public static class ByReference extends WrapIDebugHostEvaluator1
			implements Structure.ByReference {
	}

	public WrapIDebugHostEvaluator1() {
	}

	public WrapIDebugHostEvaluator1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT EvaluateExpression(Pointer context, WString expression, Pointer bindingContext,
			PointerByReference result, PointerByReference metadata) {
		return _invokeHR(VTIndices1.EVALUATE_EXPRESSION, getPointer(), context, expression,
			bindingContext, result, metadata);
	}

	@Override
	public HRESULT EvaluateExtendedExpression(Pointer context, WString expression,
			Pointer bindingContext, PointerByReference result, PointerByReference metadata) {
		return _invokeHR(VTIndices1.EVALUATE_EXTENDED_EXPRESSION, getPointer(), context, expression,
			bindingContext, result, metadata);
	}

}
