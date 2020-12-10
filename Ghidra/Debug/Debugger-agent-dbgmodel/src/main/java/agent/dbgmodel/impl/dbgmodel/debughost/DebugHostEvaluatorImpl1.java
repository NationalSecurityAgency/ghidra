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
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectImpl;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostEvaluator1;

public class DebugHostEvaluatorImpl1 implements DebugHostEvaluatorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostEvaluator1 jnaData;

	public DebugHostEvaluatorImpl1(IDebugHostEvaluator1 jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject evaluateExpression(DebugHostContext context,
			WString expression, ModelObject bindingContext) {
		Pointer pContext = context.getPointer();
		Pointer pBindingContext = bindingContext.getPointer();
		PointerByReference ppResult = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		jnaData.EvaluateExpression(pContext, expression, pBindingContext, ppResult, ppMetadata);

		return ModelObjectImpl.getObjectWithMetadata(ppResult, ppMetadata);
	}

	@Override
	public ModelObject evaluateExtendedExpression(DebugHostContext context, WString expression,
			ModelObject bindingContext) {
		Pointer pContext = context.getPointer();
		Pointer pBindingContext = bindingContext.getPointer();
		PointerByReference ppResult = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		jnaData.EvaluateExtendedExpression(pContext, expression, pBindingContext, ppResult,
			ppMetadata);

		return ModelObjectImpl.getObjectWithMetadata(ppResult, ppMetadata);
	}

}
