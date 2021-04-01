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

import java.util.List;
import java.util.Map;

import com.sun.jdi.ThreadGroupReference;

import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "ElementsContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetObject.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetElementsContainer extends JdiModelTargetObjectImpl
		implements JdiEventsListenerAdapter {

	protected static String keyGroup(ThreadGroupReference group) {
		return PathUtils.makeKey(group.name());
	}

	protected final Map<String, JdiModelTargetElementsContainer> threadGroupsById =
		new WeakValueHashMap<>();

	public JdiModelTargetElementsContainer(JdiModelTargetObject parent, String name) {
		super(parent, name);
	}

	public void addElements(List<? extends TargetObject> els) {
		setElements(els, Map.of(), "Initialized");
	}

}
