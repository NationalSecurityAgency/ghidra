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
package ghidra.dbg.test;

import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.test.AbstractDebuggerModelTest.DebuggerTestSpecimen;
import ghidra.dbg.testutil.DummyProc;

public interface ProvidesTargetViaAttachSpecimen extends RequiresTarget, RequiresAttachSpecimen {

	void setDummy(DummyProc dummy);

	AbstractDebuggerModelTest getTest();

	@Override
	default TargetObject obtainTarget() throws Throwable {
		TargetAttacher attacher = getTest().findAttacher();
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		waitAcc(attacher);
		DummyProc dummy = specimen.runDummy();
		setDummy(dummy);
		attacher.attach(dummy.pid);
		return retryForProcessRunning(specimen, getTest());
	}
}
