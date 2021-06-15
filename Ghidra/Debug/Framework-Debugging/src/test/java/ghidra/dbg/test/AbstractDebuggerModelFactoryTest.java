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

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import ghidra.dbg.DebugModelConventions.AsyncAccess;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.util.Msg;

public abstract class AbstractDebuggerModelFactoryTest extends AbstractDebuggerModelTest {

	protected abstract Map<String, Object> getFailingFactoryOptions();

	@Test
	public void testBuildAndClose() throws Throwable {
		m.build();
		assertNotNull(m.getModel());
	}

	@Test
	public void testBuildFailingOptionsErr() throws Throwable {
		for (Map.Entry<String, Object> bad : getFailingFactoryOptions().entrySet()) {
			Map<String, Object> options = new HashMap<>(m.getFactoryOptions());
			options.put(bad.getKey(), bad.getValue());
			try {
				m.buildModel(options);
				fail();
			}
			catch (Exception ex) {
				if (!DebuggerModelTerminatingException.isIgnorable(ex)) {
					throw ex;
				}
				// Pass
			}
		}
	}

	@Test
	public void testPing() throws Throwable {
		m.build();
		waitOn(m.getModel().ping("Hello, Ghidra Async Debugging!"));
	}

	@Test
	public void testWaitRootAccess() throws Throwable {
		m.build();

		TargetObject root = m.getRoot();
		AsyncAccess access = access(root);
		waitAcc(access);
	}

	@Test
	public void testHasNonEnumerableRootSchema() throws Throwable {
		m.build();

		TargetObjectSchema rootSchema = m.getModel().getRootSchema();
		Msg.info(this, rootSchema.getContext());
		assertFalse(rootSchema instanceof EnumerableTargetObjectSchema);
	}

	@Test
	public void testNonExistentPathGivesNull() throws Throwable {
		m.build();

		TargetObject root = m.getRoot();
		waitAcc(root);
		TargetObject noExist = waitOn(root.fetchSuccessor(m.getBogusPath()));
		assertNull(noExist);
	}
}
