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
package ghidra.app.plugin.core.debug.gui.tracermi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Component;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.InvocationDialogHelper;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteMethod;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.TestRemoteParameter;
import ghidra.async.SwingExecutorService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.framework.options.PropertyBoolean;
import ghidra.trace.model.target.iface.TraceMethod.Param;
import ghidra.trace.model.target.iface.TraceMethod.ParameterDescription;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema.MinimalSchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;

public class RemoteMethodInvocationDialogTest extends AbstractGhidraHeadedDebuggerTest {

	private static final SchemaContext CTX = MinimalSchemaContext.INSTANCE;

	public static TestRemoteMethod createTestMethod(Method m) {
		Map<String, RemoteParameter> params = new LinkedHashMap<>();
		for (Parameter p : m.getParameters()) {
			TestRemoteParameter parameter = createParameter(p);
			params.put(parameter.name(), parameter);
		}
		return new TestRemoteMethod(m.getName(), ActionName.name(m.getName()), "Test",
			"A test method", params,
			PrimitiveTraceObjectSchema.schemaForPrimitive(m.getReturnType()));
	}

	public static TestRemoteParameter createParameter(Parameter p) {
		ParameterDescription<?> desc = ParameterDescription.annotated(p);
		TraceObjectSchema schema = PrimitiveTraceObjectSchema.schemaForPrimitive(desc.type);
		if (schema == PrimitiveTraceObjectSchema.OBJECT ||
			schema == PrimitiveTraceObjectSchema.ANY) {
			schema = CTX.getSchema(new SchemaName(desc.schema));
		}
		return new TestRemoteParameter(desc.name, schema, desc.required, desc.defaultValue,
			desc.display, desc.description);
	}

	public static Map<String, Object> getDefaults(RemoteMethod method) {
		Map<String, Object> result = new HashMap<>();
		for (Map.Entry<String, RemoteParameter> ent : method.parameters().entrySet()) {
			result.put(ent.getKey(), ent.getValue().getDefaultValue());
		}
		return result;
	}

	record TestBits(TestRemoteMethod method, CompletableFuture<Map<String, ValStr<?>>> future,
			InvocationDialogHelper<RemoteParameter, ?> helper) {
		Component getComponent(String name) {
			return helper.getEditorComponent(method.parameters().get(name));
		}

		void setArg(String name, Object value) {
			helper.setArg(method.parameters().get(name), value);
		}

		Map<String, Object> invoke() throws Exception {
			helper.invoke();
			Map<String, ValStr<?>> args = future.get(1, TimeUnit.SECONDS);
			return args == null ? null : ValStr.toPlainMap(args);
		}
	}

	protected TestBits startTest(Method m) throws Exception {
		TestRemoteMethod method = createTestMethod(m);
		Map<String, Object> defaults = getDefaults(method);

		Map<String, ValStr<?>> defs = ValStr.fromPlainMap(defaults);
		RemoteMethodInvocationDialog dialog =
			new RemoteMethodInvocationDialog(tool, CTX, method.display(), method.display(), null);
		CompletableFuture<Map<String, ValStr<?>>> future = CompletableFuture.supplyAsync(
			() -> dialog.promptArguments(method.parameters(), defs, defs),
			SwingExecutorService.LATER);
		// Yes, I have it in hand, but I still must wait for it to appear on screen.
		InvocationDialogHelper<RemoteParameter, ?> helper =
			InvocationDialogHelper.waitFor(RemoteMethodInvocationDialog.class);

		return new TestBits(method, future, helper);
	}

	public static class MethodTakesBooleanPrimitive {
		public void theMethod(@Param(name = "b") boolean b) {
		}
	}

	@Test
	public void testBooleanPrimitiveField() throws Exception {
		TestBits bits =
			startTest(MethodTakesBooleanPrimitive.class.getMethod("theMethod", boolean.class));
		assertTrue(bits.getComponent("b") instanceof PropertyBoolean);
		bits.setArg("b", true);
		Map<String, Object> values = bits.invoke();
		assertEquals(true, values.get("b"));
	}

	public static class MethodTakesBooleanBoxed {
		public void theMethod(@Param(name = "b") Boolean b) {
		}
	}

	@Test
	public void testBooleanBoxedField() throws Exception {
		TestBits bits =
			startTest(MethodTakesBooleanBoxed.class.getMethod("theMethod", Boolean.class));
		assertTrue(bits.getComponent("b") instanceof PropertyBoolean);
		bits.setArg("b", true);
		Map<String, Object> values = bits.invoke();
		assertEquals(true, values.get("b"));
	}
}
