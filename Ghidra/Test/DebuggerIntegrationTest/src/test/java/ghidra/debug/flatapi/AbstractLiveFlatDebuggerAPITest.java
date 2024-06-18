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
package ghidra.debug.flatapi;

import java.util.function.BooleanSupplier;
import java.util.function.Function;

import org.junit.Test;

import ghidra.app.script.GhidraState;

public abstract class AbstractLiveFlatDebuggerAPITest<API extends FlatDebuggerAPI>
		extends AbstractFlatDebuggerAPITest<API> {

	protected class TestFlatAPI implements FlatDebuggerAPI {
		protected final GhidraState state =
			new GhidraState(env.getTool(), env.getProject(), program, null, null, null);

		@Override
		public GhidraState getState() {
			return state;
		}
	}

	protected abstract void runTestResume(BooleanSupplier resume) throws Throwable;

	@Test
	public void testResumeGivenThread() throws Throwable {
		runTestResume(() -> api.resume(api.getCurrentThread()));
	}

	@Test
	public void testResumeGivenTrace() throws Throwable {
		runTestResume(() -> api.resume(api.getCurrentTrace()));
	}

	@Test
	public void testResume() throws Throwable {
		runTestResume(api::resume);
	}

	protected abstract void runTestInterrupt(BooleanSupplier interrupt) throws Throwable;

	@Test
	public void testInterruptGivenThread() throws Throwable {
		runTestInterrupt(() -> api.interrupt(api.getCurrentThread()));
	}

	@Test
	public void testInterruptGivenTrace() throws Throwable {
		runTestInterrupt(() -> api.interrupt(api.getCurrentTrace()));
	}

	@Test
	public void testInterrupt() throws Throwable {
		runTestInterrupt(api::interrupt);
	}

	protected abstract void runTestKill(BooleanSupplier kill) throws Throwable;

	@Test
	public void testKillGivenThread() throws Throwable {
		runTestKill(() -> api.kill(api.getCurrentThread()));
	}

	@Test
	public void testKillGivenTrace() throws Throwable {
		runTestKill(() -> api.kill(api.getCurrentTrace()));
	}

	@Test
	public void testKill() throws Throwable {
		runTestKill(api::kill);
	}

	protected abstract void runTestExecuteCapture(Function<String, String> executeCapture)
			throws Throwable;

	@Test
	public void testExecuteCaptureGivenTrace() throws Throwable {
		runTestExecuteCapture(cmd -> api.executeCapture(api.getCurrentTrace(), cmd));
	}

	@Test
	public void testExecuteCapture() throws Throwable {
		runTestExecuteCapture(api::executeCapture);
	}
}
