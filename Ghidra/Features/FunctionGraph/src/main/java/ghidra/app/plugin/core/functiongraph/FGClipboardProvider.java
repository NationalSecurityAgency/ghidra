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
package ghidra.app.plugin.core.functiongraph;

import java.awt.Rectangle;
import java.awt.datatransfer.Transferable;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.internal.EmptyLayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import generic.text.TextLayoutGraphics;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class FGClipboardProvider extends CodeBrowserClipboardProvider {

	private FGController controller;

	FGClipboardProvider(PluginTool tool, FGController controller) {
		super(tool, controller.getProvider());
		this.controller = controller;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return false;
		}
		return context.getComponentProvider() == componentProvider;
	}

	/**
	 * Overridden because we don't have a single listing model from which to copy, but rather 
	 * many different ones, depending upon the which vertex contains the selection.
	 */
	@Override
	protected Transferable copyCode(TaskMonitor monitor) {
		try {
			TextLayoutGraphics g = new TextLayoutGraphics();

			Rectangle rect = new Rectangle(2048, 2048);

			AddressRangeIterator rangeItr = currentSelection.getAddressRanges();
			while (rangeItr.hasNext()) {
				AddressRange curRange = rangeItr.next();
				Address curAddress = curRange.getMinAddress();
				Address maxAddress = curRange.getMaxAddress();
				while (!monitor.isCancelled()) {
					if (curAddress != null && curAddress.compareTo(maxAddress) > 0) {
						break;
					}

					curAddress = copyDataForAddress(curAddress, curRange, g, rect);
					if (curAddress == null) {
						break;
					}
				}
			}

			return createStringTransferable(g.getBuffer().toString());
		}
		catch (Exception e) {
			String message = "Copy failed: " + ExceptionUtils.getMessage(e);
			Msg.error(this, message, e);
			tool.setStatusInfo(message, true);
		}

		return null;
	}

	private Address copyDataForAddress(Address address, AddressRange currentRange,
			TextLayoutGraphics g, Rectangle rectangle) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		FGVertex vertex = functionGraph.getVertexForAddress(address);
		if (vertex == null) {
			return null; // shouldn't happen
		}

		ListingModel listingModel = vertex.getListingModel(address);

		// Add the layout for the present address
		Layout layout = listingModel.getLayout(address, false);
		if (layout != null) {
			LayoutBackgroundColorManager layoutColorMap =
				new EmptyLayoutBackgroundColorManager(PAINT_CONTEXT.getBackground());
			layout.paint(null, g, PAINT_CONTEXT, rectangle, layoutColorMap, null);
			g.flush();
		}

		// Get the next Address and update the page index
		if (address.equals(currentRange.getMaxAddress())) {
			return null;
		}

		Address addressAfter = listingModel.getAddressAfter(address);
		if (addressAfter != null) {
			return addressAfter;
		}

		// A null address could mean that we have reached the end of the listing for the given
		// vertex.  If that is the case, we should look the next address by adding to the current
		// address.  This will allow a future call to this method to get the vertex that contains
		// that address.
		Address nextAddress = null;
		try {
			nextAddress = address.add(layout.getIndexSize());
		}
		catch (AddressOutOfBoundsException oobe) {
			// ignore and give up!
		}

		return nextAddress;
	}
}
