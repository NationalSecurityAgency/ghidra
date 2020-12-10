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

import com.sun.jdi.Type;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;

public class JdiModelTargetType extends JdiModelTargetObjectImpl {

	protected final Type type;

	public JdiModelTargetType(JdiModelTargetObject object, Type type) {
		this(object, type.toString(), type);
	}

	public JdiModelTargetType(JdiModelTargetObject object, String id, Type type) {
		super(object, id, type);
		this.type = type;

		changeAttributes(List.of(), List.of(), Map.of( //
			"Signature", type.signature() //
		), "Initialized");
	}

	@Override
	public String getDisplay() {
		return type == null ? super.getDisplay() : type.name();
	}

}
