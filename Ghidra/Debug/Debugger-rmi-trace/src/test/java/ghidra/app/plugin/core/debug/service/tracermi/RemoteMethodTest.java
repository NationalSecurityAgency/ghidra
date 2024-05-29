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
package ghidra.app.plugin.core.debug.service.tracermi;

import static ghidra.app.plugin.core.debug.gui.model.DebuggerModelProviderTest.CTX;

import java.util.Map;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteMethod;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteParameter;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;

public class RemoteMethodTest extends AbstractGhidraHeadedDebuggerTest {
	@Test
	public void testRemoteMethodValidateObjectGivenObject() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("obj", EnumerableTargetObjectSchema.OBJECT.getName(), true,
				null, "Arg1", "An argument"));

		createTrace();

		TraceObject root;
		try (Transaction tx = tb.startTransaction()) {
			TraceObjectValue rv = tb.trace.getObjectManager()
					.createRootObject(CTX.getSchema(new SchemaName("Session")));
			root = rv.getChild();
		}

		method.validate(Map.of("obj", root));
	}

	@Test
	public void testRemoteMethodValidateObjectGivenProcess() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("obj", EnumerableTargetObjectSchema.OBJECT.getName(), true,
				null, "Arg1", "An argument"));

		createTrace();

		TraceObject process;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(CTX.getSchema(new SchemaName("Session")));
			process =
				tb.trace.getObjectManager().createObject(TraceObjectKeyPath.parse("Processes[0]"));
			process.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}

		method.validate(Map.of("obj", process));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRemoteMethodValidateObjectGivenInt() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("obj", EnumerableTargetObjectSchema.OBJECT.getName(), true,
				null, "Arg1", "An argument"));

		method.validate(Map.of("obj", 1));
	}

	@Test
	public void testRemoteMethodValidateProcessGivenProcess() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("proc", new SchemaName("Process"), true,
				null, "Proc1", "A Process argument"));

		createTrace();

		TraceObject process;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(CTX.getSchema(new SchemaName("Session")));
			process =
				tb.trace.getObjectManager().createObject(TraceObjectKeyPath.parse("Processes[0]"));
			process.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}

		method.validate(Map.of("proc", process));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRemoteMethodValidateProcessGivenInt() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("proc", new SchemaName("Process"), true,
				null, "Proc1", "A Process argument"));

		// Otherwise "Process" schema doesn't exist
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(CTX.getSchema(new SchemaName("Session")));
		}

		method.validate(Map.of("proc", 1));
	}

	@Test
	public void testRemoteMethodValidateAnyGivenInteger() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("arg", EnumerableTargetObjectSchema.ANY.getName(), true,
				null, "Arg1", "An argument"));

		method.validate(Map.of("arg", 1));
	}

	@Test
	public void testRemoteMethodValidateAnyGivenObject() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("arg", EnumerableTargetObjectSchema.ANY.getName(), true,
				null, "Arg1", "An argument"));

		createTrace();

		TraceObject root;
		try (Transaction tx = tb.startTransaction()) {
			TraceObjectValue rv = tb.trace.getObjectManager()
					.createRootObject(CTX.getSchema(new SchemaName("Session")));
			root = rv.getChild();
		}

		method.validate(Map.of("arg", root));
	}

	@Test
	public void testRemoteMethodValidateAnyGivenProcess() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("arg", EnumerableTargetObjectSchema.ANY.getName(), true,
				null, "Arg1", "An argument"));

		createTrace();

		TraceObject process;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(CTX.getSchema(new SchemaName("Session")));
			process =
				tb.trace.getObjectManager().createObject(TraceObjectKeyPath.parse("Processes[0]"));
			process.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}

		method.validate(Map.of("arg", process));
	}

	@Test
	public void testRemoteMethodValidateIntegerGivenInteger() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("arg", EnumerableTargetObjectSchema.INT.getName(), true,
				null, "Arg1", "An argument"));

		method.validate(Map.of("arg", 1));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRemoteMethodValidateIntegerGivenLong() throws Throwable {
		RemoteMethod method = new TestRemoteMethod("test", ActionName.name("test"), "Test",
			"A test method", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("arg", EnumerableTargetObjectSchema.INT.getName(), true,
				null, "Arg1", "An argument"));

		method.validate(Map.of("arg", 1L));
	}
}
