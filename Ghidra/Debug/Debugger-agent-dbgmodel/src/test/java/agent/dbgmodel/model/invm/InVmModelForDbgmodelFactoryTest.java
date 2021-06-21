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
package agent.dbgmodel.model.invm;

import agent.dbgeng.model.AbstractModelForDbgengFactoryTest;
import ghidra.dbg.testutil.TestDebuggerModelProvider.ModelHost.WithoutThreadValidation;

public class InVmModelForDbgmodelFactoryTest extends AbstractModelForDbgengFactoryTest {

	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgmodelModelHost();
	}

	@Override
	public void validateCompletionThread() {
		super.validateCompletionThread();
	}

	/**
	 * The externally-accessible fetchX methods are being invoked internally. Unfortunately, this
	 * demarcation was not made clear at the beginning, so now, adding a gate kicks internal object
	 * retrieval off the DebugClient thread, which spells disaster for synchronization. The "real
	 * fix" will be to write internal object retrieval methods. These internal implementations will
	 * probably be left to each particular model. Dbgeng/model should be able to implement them
	 * synchronously. External invocations will still need to be handed to the DebugClient thread
	 * asynchronously. For now, we're going to disable the assertion.
	 */
	@Override
	public void testNonExistentPathGivesNull() throws Throwable {
		try (WithoutThreadValidation wtv = m.withoutThreadValidation()) {
			super.testNonExistentPathGivesNull();
		}
	}
}
