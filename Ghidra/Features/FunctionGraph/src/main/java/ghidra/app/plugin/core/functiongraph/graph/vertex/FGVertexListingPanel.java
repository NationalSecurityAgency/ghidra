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

import java.awt.Color;
import java.awt.Dimension;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.*;
import ghidra.app.plugin.core.functiongraph.FGColorProvider;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class FGVertexListingPanel extends ListingPanel {

	private ListingModelListener listener = new ListingModelListener() {
		@Override
		public void dataChanged(boolean updateImmediately) {
			//
			// Unusual Code Alert!: when the data of the listing changes its preferred size
			// 						may also change.  If we don't invalidate the containing
			//                      Java component, then the cached preferred size will be 
			//                      invalid.
			// 
			getFieldPanel().invalidate();
			controller.repaint();
		}

		@Override
		public void modelSizeChanged() {
			// don't care
		}
	};

	private FGController controller;
	private AddressSetView addressSetView;
	private Dimension preferredSizeCache;
	private Dimension lastParentPreferredSize;

	FGVertexListingPanel(final FGController controller, FormatManager formatManager,
			Program program, AddressSetView view) {
		super(formatManager);

		this.controller = controller;
		this.addressSetView = view;

		setNeverSroll(); // must be before setProgram()
		setProgram(program);
		ListingModel model = getListingModel();
		model.addListener(listener);

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		Color color = options.getDefaultVertexBackgroundColor();
		setTextBackgroundColor(color);

		FGColorProvider colorProvider = controller.getColorProvider();
		if (!colorProvider.isUsingCustomColors()) {
			enablePropertyBasedColorModel(true); // turn on user colors in the graph
		}
	}

	@Override
	public void setView(AddressSetView view) {
		this.addressSetView = view;
		super.setView(view);
	}

	@Override
	protected ListingModel createListingModel(Program program) {
		return new FGVertexListingModel(program, getFormatManager());
	}

	/**
	 * Overridden to set the view before the parent class notifies the listeners.  This prevents
	 * our methods that calculate preferred size from going 'out to lunch' when attempting to
	 * examine the entire program instead of just the given view.
	 * 
	 * @param model The listing model needed by the layout model	 * 
	 * @return the new model adapter
	 */
	@Override
	protected ListingModelAdapter createLayoutModel(ListingModel model) {
		ListingModelAdapter adapter = super.createLayoutModel(model);
		if (model != null) {
			adapter.setAddressSet(addressSetView);
		}
		return adapter;
	}

	@Override
	protected FieldPanel createFieldPanel(LayoutModel model) {
		return new FGVertexFieldPanel(model);
	}

	@Override
	public Dimension getPreferredSize() {

		Dimension preferredSize = super.getPreferredSize();
		int maxWidth = getFormatManager().getMaxWidth();
		if (preferredSize.width < maxWidth) {
			preferredSize.width += 10; // some padding on the end to avoid clipping
		}

		return preferredSize;
	}

	// Overridden, as we wish to customize our width to be as small as possible, based upon the format
	@Override
	protected int getNewWindowDefaultWidth() {
		return 0;
	}

	public void refreshModel() {
		FGVertexListingModel fgModel = (FGVertexListingModel) getListingModel();
		if (fgModel.refresh()) {
			preferredSizeCache = null;
		}
	}

	//
	// Overridden to allow for a smaller preferred size, as dictated by the layout
	//
	private class FGVertexFieldPanel extends FieldPanel {

		public FGVertexFieldPanel(LayoutModel model) {
			super(model);
		}

		@Override
		public Dimension getPreferredSize() {

			Dimension preferredSize = super.getPreferredSize();
			if (preferredSize.equals(lastParentPreferredSize) && preferredSizeCache != null) {
				return preferredSizeCache;
			}

			lastParentPreferredSize = preferredSize;
			LayoutModel layoutModel = getLayoutModel();
			List<Layout> layouts = getAllLayouts(layoutModel);
			int largestWidth = 0;
			for (Layout layout : layouts) {
				int width = layout.getCompressableWidth();
				if (width > largestWidth) {
					largestWidth = width;
				}
			}

			preferredSize.width = largestWidth;
			preferredSizeCache = preferredSize;
			return preferredSize;
		}

		private List<Layout> getAllLayouts(LayoutModel layoutModel) {
			List<Layout> list = new ArrayList<>();
			BigInteger index = BigInteger.ZERO;
			Layout layout = layoutModel.getLayout(index);
			while (layout != null) {
				list.add(layout);
				index = layoutModel.getIndexAfter(index);
				layout = layoutModel.getLayout(index);
			}

			return list;
		}
	}
}
