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
import com.sun.jdi.Field;
import com.sun.jdi.request.*;

import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Field",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(type = Void.class)
	})
public class JdiModelTargetField extends JdiModelTargetObjectImpl {

	protected final Field field;

	private JdiModelTargetType type;
	private JdiModelTargetReferenceType declaringType;
	private JdiModelTargetAttributesContainer addedAttributes;

	public JdiModelTargetField(JdiModelTargetObject fields, Field field, boolean isElement) {
		super(fields, field.toString(), field, isElement);
		this.field = field;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TYPE_ATTRIBUTE_NAME, field.typeName() //
		), "Initialized");
	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("isEnumConstant", field.isEnumConstant());
		attrs.put("isFinal", field.isFinal());
		try {
			attrs.put("isPackagePrivate", field.isPackagePrivate());
			attrs.put("isPrivate", field.isPrivate());
			attrs.put("isProtected", field.isProtected());
			attrs.put("isPublic", field.isPublic());
		}
		catch (Exception e) {
			if (e instanceof ClassNotLoadedException) {
				attrs.put("status", "Class not loaded");
			}
		}
		attrs.put("isStatic", field.isStatic());
		attrs.put("isSynthetic", field.isSynthetic());
		attrs.put("isTransient", field.isTransient());
		attrs.put("isVolatile", field.isVolatile());
		attrs.put("modifiers", field.modifiers());
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		this.declaringType = (JdiModelTargetReferenceType) getInstance(field.declaringType());

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			addedAttributes //		
		), Map.of( //
			"Declaring Type", declaringType //
		), "Initialized");

		try {
			this.type = (JdiModelTargetType) getInstance(field.type());
			if (type != null) {
				changeAttributes(List.of(), List.of(), Map.of( //
					"Type", type //
				), "Initialized");
			}
		}
		catch (ClassNotLoadedException e) {
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
		return field == null ? super.getDisplay() : field.name();
	}

	public JdiBreakpointInfo addAccessWatchpoint() {
		EventRequestManager eventManager = field.virtualMachine().eventRequestManager();
		AccessWatchpointRequest request = eventManager.createAccessWatchpointRequest(field);
		request.enable();
		return new JdiBreakpointInfo(request);
	}

	public JdiBreakpointInfo addModificationWatchpoint() {
		EventRequestManager eventManager = field.virtualMachine().eventRequestManager();
		ModificationWatchpointRequest request =
			eventManager.createModificationWatchpointRequest(field);
		request.enable();
		return new JdiBreakpointInfo(request);
	}

}
