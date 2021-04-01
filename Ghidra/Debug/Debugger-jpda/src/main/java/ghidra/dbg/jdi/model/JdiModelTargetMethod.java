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

import com.sun.jdi.*;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Method",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(type = Object.class)
	})
public class JdiModelTargetMethod extends JdiModelTargetObjectImpl {

	protected final Method method;

	private JdiModelTargetLocation location;
	private JdiModelTargetAttributesContainer addedAttributes;
	private JdiModelTargetTypeContainer argumentTypes;
	private JdiModelTargetLocalVariableContainer arguments;
	private JdiModelTargetLocationContainer locations;
	private JdiModelTargetLocalVariableContainer variables;
	private JdiModelTargetType returnType;

	public JdiModelTargetMethod(JdiModelTargetObject parent, Method method, boolean isElement) {
		super(parent, method.toString(), method, isElement);
		this.method = method;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");

	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("isAbstract", method.isAbstract());
		attrs.put("isBridge", method.isBridge());
		attrs.put("isStatic", method.isStatic());
		attrs.put("isConstructor", method.isConstructor());
		attrs.put("isDefault", method.isDefault());
		attrs.put("isFinal", method.isFinal());
		attrs.put("isNative", method.isNative());
		attrs.put("isObsolete", method.isObsolete());
		attrs.put("isStatic", method.isStatic());
		attrs.put("isStaticInitializer", method.isStaticInitializer());
		attrs.put("isSynchronized", method.isSynchronized());
		attrs.put("isSynthetic", method.isSynthetic());
		try {
			attrs.put("isPackagePrivate", method.isPackagePrivate());
			attrs.put("isPrivate", method.isPrivate());
			attrs.put("isProtected", method.isProtected());
			attrs.put("isPublic", method.isPublic());
		}
		catch (Exception e) {
			if (e instanceof ClassNotLoadedException) {
				attrs.put("status", "Class not loaded");
			}
		}
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			addedAttributes //
		), Map.of("Argument Types", method.argumentTypeNames(), //
			"Return Type", method.returnTypeName() //
		), "Initialized");

		this.location = method.location() == null ? null
				: new JdiModelTargetLocation(parent, method.location(), false);
		if (location != null) {
			changeAttributes(List.of(), List.of( //
				location //		
			), Map.of(), "Initialized");
		}
		try {
			this.arguments =
				new JdiModelTargetLocalVariableContainer(this, "Arguments", method.arguments());
			if (arguments != null) {
				changeAttributes(List.of(), List.of( //
					arguments //
				), Map.of(), "Initialized");
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
		try {
			this.argumentTypes =
				new JdiModelTargetTypeContainer(this, "Argument Types", method.argumentTypes());
			if (argumentTypes != null) {
				changeAttributes(List.of(), List.of( //
					argumentTypes //
				), Map.of(), "Initialized");
			}
		}
		catch (ClassNotLoadedException e) {
			// Ignore
		}
		try {
			locations =
				new JdiModelTargetLocationContainer(this, "Locations", method.allLineLocations());
			if (locations != null) {
				changeAttributes(List.of(), List.of( //
					locations //
				), Map.of(), "Initialized");
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
		try {
			returnType = (JdiModelTargetType) getInstance(method.returnType());
			if (returnType != null) {
				changeAttributes(List.of(), List.of( //
					returnType //		
				), Map.of(), "Initialized");
			}
		}
		catch (ClassNotLoadedException e) {
			// Ignore
		}
		try {
			this.variables =
				new JdiModelTargetLocalVariableContainer(this, "Variables", method.variables());
			if (variables != null) {
				changeAttributes(List.of(), List.of( //
					variables //		
				), Map.of(), "Initialized");
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return method == null ? super.getDisplay() : method.name();
	}

}
