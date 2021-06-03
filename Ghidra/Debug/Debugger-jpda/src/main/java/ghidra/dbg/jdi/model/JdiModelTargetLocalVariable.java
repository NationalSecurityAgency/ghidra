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

import com.sun.jdi.ClassNotLoadedException;
import com.sun.jdi.LocalVariable;

import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "LocalVariable",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(name = "Generic Signature", type = String.class),
		@TargetAttributeType(name = "Signature", type = String.class),
		@TargetAttributeType(name = "Type", type = String.class, required = true),
		@TargetAttributeType(type = Void.class)
	})
public class JdiModelTargetLocalVariable extends JdiModelTargetObjectImpl {

	String IS_ARGUMENT_ATTRIBUTE_NAME = "IsArg";
	String VISIBLE_TYPE_ATTRIBUTE_NAME = "Type";

	protected final LocalVariable var;
	private JdiModelTargetAttributesContainer addedAttributes;

	public JdiModelTargetLocalVariable(JdiModelTargetLocalVariableContainer variables,
			LocalVariable var, boolean isElement) {
		super(variables, var.name(), var, isElement);
		this.var = var;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, var.name(), //
			VISIBLE_TYPE_ATTRIBUTE_NAME, var.typeName() //
		), "Initialized");

	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("isArgument", var.isArgument());
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			addedAttributes //
		), Map.of( //
			"Signature", var.signature() //
		), "Initialized");

		try {
			JdiModelTargetType type = (JdiModelTargetType) getInstance(var.type());
			changeAttributes(List.of(), List.of(), Map.of( //
				"Type", type //
			), "Initialized");
		}
		catch (ClassNotLoadedException e) {
			// Ignore
		}
		String genericSignature = var.genericSignature();
		if (genericSignature != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				"Generic Signature", genericSignature //
			), "Initialized");
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return var == null ? super.getDisplay() : var.name();
	}

}
