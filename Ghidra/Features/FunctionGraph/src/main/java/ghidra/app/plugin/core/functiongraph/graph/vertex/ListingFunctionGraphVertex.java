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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.SystemUtilities;

public class ListingFunctionGraphVertex extends AbstractFunctionGraphVertex {

	private ListingGraphComponentPanel component;

	public ListingFunctionGraphVertex(FGController controller, AddressSetView addressSet,
			FlowType flowType, boolean isEntry) {
		super(controller, controller.getProgram(), addressSet, flowType, isEntry);
	}

	/** Copy constructor */
	private ListingFunctionGraphVertex(FGController controller, ListingFunctionGraphVertex vertex) {
		super(controller, vertex);
	}

	@Override
	public ListingFunctionGraphVertex cloneVertex(FGController newController) {
		return new ListingFunctionGraphVertex(newController, this);
	}

	@Override
	boolean hasLoadedComponent() {
		return component != null;
	}

	@Override
	AbstractGraphComponentPanel doGetComponent() {
		if (component == null) {
			SystemUtilities.assertThisIsTheSwingThread(
				"Cannot create vertex component " + "off of the Swing thread");

			FGController controller = getController();
			component = new ListingGraphComponentPanel(this, controller, controller.getTool(),
				getProgram(), getAddresses());

			if (pendingRestoreColor != null) {
				component.restoreColor(pendingRestoreColor);
				pendingRestoreColor = null;
			}
		}
		return component;
	}

	@Override
	public void dispose() {
		super.dispose();
		if (component != null) {
			component.dispose();
			component = null;
		}
	}
}
