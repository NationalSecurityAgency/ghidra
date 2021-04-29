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

import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "AttributesContainer",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class JdiModelTargetAttributesContainer extends JdiModelTargetObjectImpl
		implements JdiEventsListenerAdapter {

	public JdiModelTargetAttributesContainer(JdiModelTargetObject parent, String name) {
		super(parent, name);
	}

	public void addAttributes(Map<String, ? extends Object> attrs) {
		setAttributes(List.of(), attrs, "Initialized");
	}

}
