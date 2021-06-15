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

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.async.AsyncReference;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.program.model.address.AddressFactory;

public class AnnotatedDebuggerAttributeListenerTest implements DebuggerModelTestUtils {
	@Test
	public void testAnnotatedListener() throws Throwable {
		AbstractDebuggerObjectModel model = new AbstractDebuggerObjectModel() {
			@Override
			public AddressFactory getAddressFactory() {
				return null;
			}
		};
		DefaultTargetModelRoot obj = new DefaultTargetModelRoot(model, "Test");

		AsyncReference<String, Void> display = new AsyncReference<>();
		DebuggerModelListener l = new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
			@AttributeCallback("_test")
			private void testChanged(TargetObject object, String disp) {
				display.set(disp, null);
			}
		};
		obj.addListener(l);
		obj.changeAttributes(List.of(), Map.ofEntries(Map.entry("_test", "Testing")), "Because");
		waitOn(display.waitValue("Testing"));

		obj.changeAttributes(List.of("_test"), Map.of(), "Because");
		waitOn(display.waitValue(null));
	}
}
