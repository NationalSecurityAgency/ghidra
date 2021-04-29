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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostEvaluator1 extends IUnknownEx {
	final IID IID_IDEBUG_HOST_EVALUATOR = new IID("0FEF9A21-577E-4997-AC7B-1C4883241D99");

	enum VTIndices1 implements VTableIndex {
		EVALUATE_EXPRESSION, //
		EVALUATE_EXTENDED_EXPRESSION, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT EvaluateExpression(Pointer context, WString expression, Pointer bindingContext,
			PointerByReference result, PointerByReference metadata);

	HRESULT EvaluateExtendedExpression(Pointer context, WString expression, Pointer bindingContext,
			PointerByReference result, PointerByReference metadata);

}
