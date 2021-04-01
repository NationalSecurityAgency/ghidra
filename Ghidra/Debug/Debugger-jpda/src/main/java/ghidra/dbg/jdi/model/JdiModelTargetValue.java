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

import com.sun.jdi.Type;
import com.sun.jdi.Value;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Value",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetValue extends JdiModelTargetObjectImpl {

	protected final Value value;
	protected final Type type;

	public JdiModelTargetValue(JdiModelTargetObject object, Value value, boolean isElement) {
		this(object, value.toString(), value, isElement);
	}

	public JdiModelTargetValue(JdiModelTargetObject object, String id, Value value,
			boolean isElement) {
		super(object, id, value, isElement);
		this.value = value;
		this.type = value.type();
	}

}
