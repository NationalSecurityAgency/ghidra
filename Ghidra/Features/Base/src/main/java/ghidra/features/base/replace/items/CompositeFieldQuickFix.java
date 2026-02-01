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
package ghidra.features.base.replace.items;

import java.util.Map;

import ghidra.app.services.DataTypeManagerService;
import ghidra.features.base.quickfix.QuickFix;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;

/**
 * Base class for Composite field Quick Fixes. Primarily exists to host the logic for finding
 * components in a composite even as it is changing.
 */
public abstract class CompositeFieldQuickFix extends QuickFix {
	protected Composite composite;
	private int ordinal;

	/**
	 * Constructor
	 * @param program the program containing the composite.
	 * @param composite the composite being changed
	 * @param ordinal the ordinal of the field within the composite
	 * @param original the original name of the field
	 * @param newName the new name for the field
	 */
	public CompositeFieldQuickFix(Program program, Composite composite, int ordinal,
			String original, String newName) {
		super(program, original, newName);
		this.composite = composite;
		this.ordinal = ordinal;
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public String getPath() {
		return composite.getPathName();
	}

	protected DataTypeComponent findComponent(String name) {
		DataTypeComponent component = getComponentByOrdinal();
		if (component != null) {
			if (name.equals(component.getFieldName())) {
				return component;
			}
		}

		// perhaps it moved (has a different ordinal now)?
		DataTypeComponent[] components = composite.getDefinedComponents();
		for (int i = 0; i < components.length; i++) {
			if (name.equals(components[i].getFieldName())) {
				ordinal = i;
				return components[i];
			}
		}
		return null;
	}

	protected DataTypeComponent getComponentByOrdinal() {
		if (composite.isDeleted()) {
			return null;
		}
		if (ordinal >= composite.getNumComponents()) {
			return null;
		}

		return composite.getComponent(ordinal);
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("DataType", composite.getPathName());
	}

	@Override
	protected boolean navigateSpecial(ServiceProvider services, boolean fromSelectionChange) {
		DataTypeManagerService dtmService = services.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			return false;
		}

		dtmService.setDataTypeSelected(composite);

		if (!fromSelectionChange) {
			dtmService.edit(composite, getFieldName());
		}
		return true;
	}

	protected abstract String getFieldName();

	protected void editComposite(DataTypeManagerService dtmService) {
		dtmService.edit(composite);
	}
}
