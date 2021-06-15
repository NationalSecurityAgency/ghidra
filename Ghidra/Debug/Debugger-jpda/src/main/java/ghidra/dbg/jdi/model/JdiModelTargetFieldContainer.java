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

import com.sun.jdi.Field;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "FieldsContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetField.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetFieldContainer extends JdiModelTargetObjectImpl {
	// NOTE: -file-list-shared-libraries omits the main module and system-supplied DSO.

	protected final JdiModelTargetReferenceType reftype;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetField> fieldsByName = new HashMap<>();
	private boolean useAll;

	public JdiModelTargetFieldContainer(JdiModelTargetReferenceType reftype, boolean all) {
		super(reftype, all ? "Fields (All)" : "Fields");
		this.reftype = reftype;
		this.useAll = all;
	}

	protected CompletableFuture<Void> updateUsingFields(Map<String, Field> byName) {
		List<JdiModelTargetField> fields;
		synchronized (this) {
			fields =
				byName.values().stream().map(this::getTargetField).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetField m : fields) {
			fence.include(m.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), fields, Map.of(), "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, Field> map = new HashMap<>();
		List<Field> fields = useAll ? reftype.reftype.allFields() : reftype.reftype.fields();
		for (Field f : fields) {
			map.put(f.name(), f);
		}
		fieldsByName.keySet().retainAll(map.keySet());
		return updateUsingFields(map);
	}

	protected synchronized JdiModelTargetField getTargetField(Field var) {
		return fieldsByName.computeIfAbsent(var.name(),
			n -> (JdiModelTargetField) getInstance(var));
	}

	public synchronized JdiModelTargetField getTargetFieldIfPresent(String name) {
		return fieldsByName.get(name);
	}
}
