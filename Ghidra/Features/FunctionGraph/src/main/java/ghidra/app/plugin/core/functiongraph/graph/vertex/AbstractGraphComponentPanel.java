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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import javax.swing.*;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGView;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public abstract class AbstractGraphComponentPanel extends JPanel {

	protected FGController controller;
	protected FGVertex vertex;

	protected String title;

	private boolean isShowingOverride = true;
	private boolean isFocused;

	AbstractGraphComponentPanel(FGController controller, FGVertex vertex) {
		this.controller = controller;
		this.vertex = vertex;
	}

	void setShowing(boolean isShowing) {
		isShowingOverride = isShowing;
	}

	String getTitle() {
		return title;
	}

	@Override
	// overridden so that we always paint
	public boolean isShowing() {
		return isShowingOverride;
	}

	@Override
	public Dimension getSize() {
		return getPreferredSize();
	}

	FGController getController() {
		return controller;
	}

	void dispose() {
		controller = null;
		vertex = null;
	}

	protected void groupVertices() {
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> primaryViewer = view.getPrimaryGraphViewer();
		edu.uci.ics.jung.algorithms.layout.Layout<FGVertex, FGEdge> graphLayout =
			primaryViewer.getGraphLayout();
		Point2D location = graphLayout.apply(vertex);
		controller.groupSelectedVertices(location);
	}

	protected void regroupVertices() {
		controller.regroupVertices(vertex);
	}

//======================================================

	abstract Color getBackgroundColor();

	abstract Color getSelectionColor();

	abstract Color getUserDefinedColor();

	abstract Color getDefaultBackgroundColor();

	abstract void clearColor();

	abstract JComponent getHeader();

	@Override
	public abstract String getToolTipText(MouseEvent event);

	abstract ListingModel getListingModel(Address address);

	abstract JComponent getToolTipComponentForEdge(FGEdge edge);

	abstract JComponent getToolTipComponentForVertex();

	abstract boolean isSelected();

	abstract void setSelected(boolean selected);

	abstract void setCursorPosition(ProgramLocation location);

	abstract Rectangle getCursorBounds();

	abstract void setProgramSelection(ProgramSelection selection);

	abstract ProgramSelection getProgramSelection();

	abstract String getTextSelection();

	abstract void setProgramHighlight(ProgramSelection highlight);

	void setProgramLocation(ProgramLocation location) {
		setSelected(true);
		setCursorPosition(location);
	}

	abstract ProgramLocation getProgramLocation();

	boolean isDefaultBackgroundColor() {
		return getBackgroundColor().equals(Color.WHITE);
	}

	boolean isHeaderClick(Component clickedComponent) {
		if (clickedComponent == null) {
			return false;
		}

		Component header = getHeader();
		return SwingUtilities.isDescendingFrom(clickedComponent, header);
	}

	@Override
	public Rectangle getBounds() {
		Rectangle bounds = super.getBounds();
		Dimension preferredSize = getPreferredSize();
		bounds.setSize(preferredSize);
		return bounds;
	}

	abstract void setBackgroundColor(Color color);

	abstract void restoreColor(Color color);

	@Override
	public String toString() {
		return getTitle();
	}

	abstract void refreshModel();

	abstract void refreshDisplay();

	abstract void refreshDisplayForAddress(Address address);

	abstract Component getMaximizedViewComponent();

	abstract boolean isFullScreenMode();

	abstract void setFullScreenMode(boolean fullScreen);

	abstract void updateGroupAssociationStatus(boolean groupMember);

	abstract void editLabel(JComponent parentComponent);

	public void setFocused(boolean focused) {
		this.isFocused = focused;
		doSetFocused(focused);
	}

	abstract void doSetFocused(boolean focused);

	public boolean isFocused() {
		return isFocused;
	}
}
