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

import static ghidra.app.plugin.core.debug.gui.model.DebuggerModelProviderTest.*;
import static org.junit.Assert.*;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.target.TraceObjectValue;

public class ModelQueryTest extends AbstractGhidraHeadedDebuggerGUITest {
	@Test
	public void testIncludes() throws Throwable {
		createTrace();

		ModelQuery rootQuery = ModelQuery.parse("");
		ModelQuery threadQuery = ModelQuery.parse("Processes[].Threads[]");

		try (Transaction tx = tb.startTransaction()) {
			DBTraceObjectManager objects = tb.trace.getObjectManager();

			TraceObjectValue rootVal =
				objects.createRootObject(CTX.getSchema(new SchemaName("Session")));

			TraceObjectValue thread0Val =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Threads[0]"))
						.insert(Lifespan.nowOn(0), ConflictResolution.DENY)
						.getLastEntry();

			assertTrue(rootQuery.includes(Lifespan.ALL, rootVal));
			assertFalse(rootQuery.includes(Lifespan.ALL, thread0Val));

			assertFalse(threadQuery.includes(Lifespan.ALL, rootVal));
			assertTrue(threadQuery.includes(Lifespan.ALL, thread0Val));
			assertFalse(threadQuery.includes(Lifespan.before(0), thread0Val));
		}
	}

	@Test
	public void testInvolves() throws Throwable {
		createTrace();

		ModelQuery rootQuery = ModelQuery.parse("");
		ModelQuery threadQuery = ModelQuery.parse("Processes[].Threads[]");

		try (Transaction tx = tb.startTransaction()) {
			DBTraceObjectManager objects = tb.trace.getObjectManager();

			TraceObjectValue rootVal =
				objects.createRootObject(CTX.getSchema(new SchemaName("Session")));

			TraceObjectValue thread0Val =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Threads[0]"))
						.insert(Lifespan.nowOn(0), ConflictResolution.DENY)
						.getLastEntry();

			assertTrue(rootQuery.involves(Lifespan.ALL, rootVal));
			assertFalse(rootQuery.involves(Lifespan.ALL, thread0Val));

			assertTrue(threadQuery.involves(Lifespan.ALL, rootVal));
			assertTrue(threadQuery.involves(Lifespan.ALL, thread0Val));
			assertFalse(threadQuery.involves(Lifespan.before(0), thread0Val));
		}
	}
}
