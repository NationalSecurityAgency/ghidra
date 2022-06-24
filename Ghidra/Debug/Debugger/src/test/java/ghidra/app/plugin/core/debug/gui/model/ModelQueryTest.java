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
package ghidra.app.plugin.core.debug.gui.model;

import static ghidra.app.plugin.core.debug.gui.model.DebuggerModelProviderTest.CTX;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.database.UndoableTransaction;

public class ModelQueryTest extends AbstractGhidraHeadedDebuggerGUITest {
	@Test
	public void testIncludes() throws Throwable {
		createTrace();

		ModelQuery rootQuery = ModelQuery.parse("");
		ModelQuery threadQuery = ModelQuery.parse("Processes[].Threads[]");

		try (UndoableTransaction tid = UndoableTransaction.start(tb.trace, "Init", true)) {
			DBTraceObjectManager objects = tb.trace.getObjectManager();

			TraceObjectValue rootVal =
				objects.createRootObject(CTX.getSchema(new SchemaName("Session")));

			TraceObjectValue thread0Val =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Threads[0]"))
						.insert(Range.atLeast(0L), ConflictResolution.DENY)
						.getLastEntry();

			assertTrue(rootQuery.includes(Range.all(), rootVal));
			assertFalse(rootQuery.includes(Range.all(), thread0Val));

			assertFalse(threadQuery.includes(Range.all(), rootVal));
			assertTrue(threadQuery.includes(Range.all(), thread0Val));
			assertFalse(threadQuery.includes(Range.lessThan(0L), thread0Val));
		}
	}
}
