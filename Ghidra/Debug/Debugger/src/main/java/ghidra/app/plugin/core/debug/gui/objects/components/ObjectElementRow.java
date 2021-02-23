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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;

public class ObjectElementRow {

	private Map<String, ?> map;
	private TargetObject to;
	private String currentKey;

	public ObjectElementRow(TargetObjectRef ref, DebuggerObjectsProvider provider) {
		AtomicReference<TargetObject> targetObject = new AtomicReference<>();
		AtomicReference<Map<String, ?>> attributes = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			ref.fetch().handle(seq::next);
		}, targetObject).then(seq -> {
			to = targetObject.get();
			to.fetchAttributes(true).handle(seq::next);
			//to.getAttributes().thenAccept(v -> map = v);
		}, attributes).then(seq -> {
			map = attributes.get();
		}).finish();
	}

	public void setAttributes(Map<String, ?> attributes) {
		map = attributes;
	}

	public List<String> getKeys() {
		List<String> keys = new ArrayList<String>();
		keys.add("Accessor");
		if (map == null) {
			return keys;
		}
		for (String key : map.keySet()) {
			Object value = map.get(key);
			if (value instanceof TargetObject) {
				TargetObject t = (TargetObject) value;
				if (!(t instanceof TargetMethod)) {
					keys.add(key);
				}
			}
			else {
				keys.add(key);
			}
		}
		return keys;
	}

	public void setCurrentKey(String key) {
		this.currentKey = key;
	}

	public Object getValue() {
		if (currentKey.equals("Accessor")) {
			return getTargetObject().getName();
		}
		if (map == null) {
			return "";
		}
		Object value = map.get(currentKey);
		if (value instanceof TargetObject) {
			TargetObject obj = (TargetObject) value;
			Map<String, ?> attributes = obj.getCachedAttributes();
			if (attributes.containsKey(TargetObject.VALUE_ATTRIBUTE_NAME)) {
				return attributes.get(TargetObject.VALUE_ATTRIBUTE_NAME).toString();
			}
			if (attributes.containsKey(TargetObject.DISPLAY_ATTRIBUTE_NAME)) {
				return obj.getDisplay();
			}
		}
		return value == null ? "" : value;
	}

	public TargetObject getTargetObject() {
		return to;
	}

}
