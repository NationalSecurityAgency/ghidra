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
import java.util.stream.Collectors;

import com.sun.jdi.Value;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "TargetValueContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetValue.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetValueContainer extends JdiModelTargetObjectImpl {

	private List<Value> values;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetValue> valuesByName = new HashMap<>();

	public JdiModelTargetValueContainer(JdiModelTargetObject parent, String name,
			List<Value> vals) {
		super(parent, name);
		this.values = vals;
	}

	protected CompletableFuture<Void> updateUsingValues(Map<String, Value> byName) {
		List<JdiModelTargetValue> vals;
		synchronized (this) {
			vals = byName.values().stream().map(this::getTargetValue).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetValue val : vals) {
			fence.include(val.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), vals, Map.of(), "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, Value> map = new HashMap<>();
		try {
			for (Value val : values) {
				map.put(val.toString(), val);
			}
			valuesByName.keySet().retainAll(map.keySet());
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return updateUsingValues(map);
	}

	protected synchronized JdiModelTargetValue getTargetValue(Value val) {
		return valuesByName.computeIfAbsent(val.toString(),
			n -> new JdiModelTargetValue(this, val, true));
	}

	public synchronized JdiModelTargetValue getTargetValueIfPresent(String name) {
		return valuesByName.get(name);
	}
}
