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
package ghidra.dbg;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.assertEquals;

import java.util.concurrent.TimeUnit;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.dbg.target.*;
import ghidra.util.SystemUtilities;

public class DebugModelConventionsTest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected final TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder();

	@Test
	public void testFindSuitableWithinContainerSeedContainer() throws Exception {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		TargetBreakpointSpecContainer bpts = DebugModelConventions
				.findSuitable(TargetBreakpointSpecContainer.class, mb.testProcess1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertEquals(mb.testProcess1.breaks, bpts);
	}

	@Test
	public void testFindSuitableWithinContainerSeedChild() throws Exception {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		TargetBreakpointSpecContainer bpts = DebugModelConventions
				.findSuitable(TargetBreakpointSpecContainer.class, mb.testProcess1.threads)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertEquals(mb.testProcess1.breaks, bpts);
	}

	@Test
	public void testFindSuitableOutsideContainer() throws Exception {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		TargetEnvironment env = DebugModelConventions
				.findSuitable(TargetEnvironment.class, mb.testProcess1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertEquals(mb.testModel.session.environment, env);
	}

	@Test
	public void testFindSuitableAtRootSeedChild() throws Exception {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		TargetFocusScope scope = DebugModelConventions
				.findSuitable(TargetFocusScope.class, mb.testThread1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertEquals(mb.testModel.session, scope);
	}

	@Test
	@Ignore("TODO")
	public void testNearestAncestor() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testCollectAncestors() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testCollectSucccessorElements() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testIsExecution() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testFindExecution() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testSubTreeListenerAdapter() throws Exception {
		TODO(); // Possibly many tests. Separate class?
	}

	@Test
	@Ignore("TODO")
	public void testTrackAccessibility() throws Exception {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testRequestFocus() throws Exception {
		TODO();
	}
}
