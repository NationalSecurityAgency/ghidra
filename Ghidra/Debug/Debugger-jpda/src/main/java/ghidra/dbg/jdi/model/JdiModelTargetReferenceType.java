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

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;

@TargetObjectSchemaInfo(
	name = "ReferenceType",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(type = Object.class)
	})
public class JdiModelTargetReferenceType extends JdiModelTargetType implements TargetModule {

	protected final ReferenceType reftype;
	private long maxInstances = 100;

	private JdiModelTargetFieldContainer allFields;
	private JdiModelTargetMethodContainer allMethods;
	private JdiModelTargetFieldContainer fields;
	private JdiModelTargetMethodContainer methods;
	private JdiModelTargetObjectReferenceContainer instances;
	private JdiModelTargetObjectReference classObject;
	private JdiModelTargetObjectReference classLoader;
	private JdiModelTargetLocationContainer locations;

	private JdiModelTargetAttributesContainer addedAttributes;
	protected JdiModelTargetSectionContainer sections;

	public JdiModelTargetReferenceType(JdiModelTargetObject parent, ReferenceType reftype,
			boolean isElement) {
		this(parent, reftype.name(), reftype, isElement);
	}

	public JdiModelTargetReferenceType(JdiModelTargetObject parent, String id,
			ReferenceType reftype, boolean isElement) {
		super(parent, id, reftype, isElement);
		this.reftype = reftype;

		if (reftype instanceof ClassType) {
			this.sections = new JdiModelTargetSectionContainer(this);
			if (sections != null) {
				changeAttributes(List.of(), List.of( //
					sections //
				), Map.of(), "Initialized");
			}
		}

		// NB. Relevant ranges are in sections
		Address zero = impl.getAddressSpace("ram").getAddress(0L);
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, reftype.name(), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, reftype.name(), //
			RANGE_ATTRIBUTE_NAME, new AddressRangeImpl(zero, zero), //
			MODULE_NAME_ATTRIBUTE_NAME, reftype.name() //
		), "Initialized");

	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		if (reftype instanceof ArrayType) {
			return;
		}
		try {
			attrs.put("isAbstract", reftype.isAbstract());
			attrs.put("isFinal", reftype.isFinal());
			attrs.put("isInitialized", reftype.isInitialized());
			attrs.put("isPackagePrivate", reftype.isPackagePrivate());
			attrs.put("isPrepared", reftype.isPrepared());
			attrs.put("isPrivate", reftype.isPrivate());
			attrs.put("isProtected", reftype.isProtected());
			attrs.put("isPublic", reftype.isPublic());
			attrs.put("isStatic", reftype.isStatic());
			attrs.put("isVerified", reftype.isVerified());
		}
		catch (Exception e) {
			if (e instanceof ClassNotLoadedException) {
				attrs.put("status", "Class not loaded");
			}
		}
		attrs.put("defaultStratum", reftype.defaultStratum());
		attrs.put("availableStata", reftype.availableStrata());
		attrs.put("failedToInitialize", reftype.failedToInitialize());
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		this.allFields = new JdiModelTargetFieldContainer(this, true);
		this.allMethods = new JdiModelTargetMethodContainer(this, true);
		this.fields = new JdiModelTargetFieldContainer(this, false);
		this.methods = new JdiModelTargetMethodContainer(this, false);
		this.instances = new JdiModelTargetObjectReferenceContainer(this, "Objects",
			reftype.instances(maxInstances));
		this.classLoader = reftype.classLoader() == null ? null
				: new JdiModelTargetObjectReference(this, reftype.classLoader(), false);
		this.classObject = (JdiModelTargetObjectReference) getInstance(reftype.classObject());

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			allFields, //
			allMethods, //
			fields, //
			methods, //
			instances, //
			addedAttributes //
		), Map.of( //
			"Class Object", classObject //
		), "Initialized");

		try {
			this.locations =
				new JdiModelTargetLocationContainer(this, "Locations", reftype.allLineLocations());
			if (locations != null) {
				changeAttributes(List.of(), List.of( //
					locations //
				), Map.of(), "Initialized");
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
		if (classLoader != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				"Class Loader", classLoader //
			), "Initialized");
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		AsyncFence fence = new AsyncFence();
		//fence.include(methods.requestElements(true));
		return fence.ready();
	}

	@Override
	public String getDisplay() {
		return reftype == null ? super.getDisplay() : reftype.name();
	}

	public JdiModelTargetMethodContainer getAllMethods() {
		return allMethods;
	}

}
