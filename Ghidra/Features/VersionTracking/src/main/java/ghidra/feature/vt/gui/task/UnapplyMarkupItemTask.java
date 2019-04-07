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

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class UnapplyMarkupItemTask extends VtTask {

	protected final List<VTMarkupItem> markupItems;
	private final AddressCorrelation correlation;

	public UnapplyMarkupItemTask(VTSession session, AddressCorrelation correlation,
			List<VTMarkupItem> markupItems) {
		super("Reset Markup Items", session);
		this.correlation = correlation;
		this.markupItems = markupItems;

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!");
		}
	}
	
	@Override
	protected boolean shouldSuspendSessionEvents() {
		return markupItems.size() > 20;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		monitor.initialize(markupItems.size());
		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();

			try {
				maybeUnapply(markupItem);
				maybeClearStatus(markupItem);
				maybeResetDestinationAddressToDefault(markupItem, monitor);
			}
			catch (VersionTrackingApplyException e) {
				reportError(e);
			}

			monitor.incrementProgress(1);
		}
		return true;
	}

	private void maybeUnapply(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		if (markupItem.canUnapply()) {
			markupItem.unapply();
		}
	}

	private void maybeClearStatus(VTMarkupItem markupItem) {
		VTMarkupItemStatus status = markupItem.getStatus();
		if (!status.isDefault() && !status.isUnappliable()) {
			markupItem.setConsidered(VTMarkupItemConsideredStatus.UNCONSIDERED);
		}
	}

	// Note: this method currently does a bad thing to the user--it will reset the address, which
	//       may not be what they want, if all they want to do is unapply :(  I suppose an undo
	//       will let the get the address back?
	private void maybeResetDestinationAddressToDefault(VTMarkupItem markupItem, TaskMonitor monitor)
			throws CancelledException {

		Address destinationAddress = null;
		String source = null;
		if (correlation != null) {
			AddressRange range =
				correlation.getCorrelatedDestinationRange(markupItem.getSourceAddress(), monitor);
			if (range != null) {
				destinationAddress = range.getMinAddress();
				source = correlation.getName();
			}
		}

		markupItem.setDefaultDestinationAddress(destinationAddress, source);
	}
}
