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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.LocalVariable;
import com.sun.jdi.Value;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "TargetValueMap",
	elements = {
		@TargetElementType(type = Void.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = JdiModelTargetValue.class)
	},
	canonicalContainer = true)
public class JdiModelTargetValueMap extends JdiModelTargetObjectImpl {

	private Map<LocalVariable, Value> values;

	// TODO: Is it possible to load the same object twice?
	protected final Map<LocalVariable, JdiModelTargetValue> valuesByVariable = new HashMap<>();

	public JdiModelTargetValueMap(JdiModelTargetObject parent, Map<LocalVariable, Value> vals) {
		super(parent, "Value Map");
		this.values = vals;
	}

	protected CompletableFuture<Void> updateUsingValues(Map<LocalVariable, Value> byName) {
		Map<String, JdiModelTargetValue> vals = new HashMap<>();
		synchronized (this) {
			for (LocalVariable key : byName.keySet()) {
				Value val = byName.get(key);
				if (val != null) {
					JdiModelTargetValue targetValue = getTargetValue(key, val);
					vals.put(key.name(), targetValue);
				}
			}
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetValue var : vals.values()) {
			fence.include(var.init());
		}
		return fence.ready().thenAccept(__ -> {
			setAttributes(List.of(), vals, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		return updateUsingValues(values);
	}

	protected synchronized JdiModelTargetValue getTargetValue(LocalVariable var, Value val) {
		return valuesByVariable.computeIfAbsent(var,
			n -> new JdiModelTargetValue(this, val, false));
	}

	public synchronized JdiModelTargetValue getTargetValueIfPresent(LocalVariable var) {
		return valuesByVariable.get(var);
	}
}
