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
package ghidra.feature.vt.gui.task;

import java.util.List;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

public class ApplyMarkupAtDestinationAddressTask extends VtTask {

	protected final List<VTMarkupItem> markupItems;
	protected final Address destinationAddress;
	protected final ToolOptions options;

	public ApplyMarkupAtDestinationAddressTask(VTSession session, List<VTMarkupItem> markupItems,
			Address destinationAddress, ToolOptions options) {
		this("Apply Markup Item at Destination Address", session, markupItems, destinationAddress,
			options);
	}

	protected ApplyMarkupAtDestinationAddressTask(String title, VTSession session,
			List<VTMarkupItem> markupItems, Address destinationAddress, ToolOptions options) {
		super(title, session);
		this.markupItems = markupItems;
		this.options = options;

		this.destinationAddress = destinationAddress;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		monitor.initialize(markupItems.size());

		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();

			try {
				if (!SystemUtilities.isEqual(markupItem.getDestinationAddress(),
					destinationAddress)) {
					markupItem.setDestinationAddress(destinationAddress);
				}

				VTMarkupType markupType = markupItem.getMarkupType();
				VTMarkupItemApplyActionType applyAction = markupType.getApplyAction(options);
				if (applyAction == null) {
					// the default action is not applicable for the given options
					continue;
				}

				markupItem.getAssociation().setAccepted();
				markupItem.apply(applyAction, options);
			}
			catch (VersionTrackingApplyException | VTAssociationStatusException e) {
				reportError(e);
			}
			monitor.incrementProgress(1);
		}
		return true;
	}
}
