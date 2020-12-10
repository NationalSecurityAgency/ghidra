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
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.debughost.DebugHostEvaluator2;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectImpl;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostEvaluator2;

public class DebugHostEvaluatorImpl2 extends DebugHostEvaluatorImpl1
		implements DebugHostEvaluator2 {
	@SuppressWarnings("unused")
	private final IDebugHostEvaluator2 jnaData;

	public DebugHostEvaluatorImpl2(IDebugHostEvaluator2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject assignTo(ModelObject assignmentReference, ModelObject assignmentValue) {
		Pointer pAssignmentReference = assignmentReference.getPointer();
		Pointer pAssignmentValue = assignmentValue.getPointer();
		PointerByReference ppAssignmentResult = new PointerByReference();
		PointerByReference ppAssignmentMetadata = new PointerByReference();
		jnaData.AssignTo(pAssignmentReference, pAssignmentValue, ppAssignmentResult,
			ppAssignmentMetadata);

		return ModelObjectImpl.getObjectWithMetadata(ppAssignmentResult, ppAssignmentMetadata);
	}

}
