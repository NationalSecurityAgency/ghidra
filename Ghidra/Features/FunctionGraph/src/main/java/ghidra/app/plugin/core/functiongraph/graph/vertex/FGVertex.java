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

import javax.swing.JComponent;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FGVertexType;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.graph.viewer.VisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * A visual vertex that represents a code block within a function.  This class understands
 * software modeling concepts and deals with things like program selections and locations.
 */
public interface FGVertex extends VisualVertex {

	static final Color TOOLTIP_BACKGROUND_COLOR = new Color(255, 255, 230);

	public FGVertex cloneVertex(FGController newController);

	/** A chance for this vertex to save off changed settings */
	public void writeSettings(FunctionGraphVertexAttributes settings);

	/** A chance for this vertex to read in stored settings */
	public void readSettings(FunctionGraphVertexAttributes settings);

	public void restoreColor(Color color);

	public Color getUserDefinedColor();

	public FGVertexType getVertexType();

	/**
	 * Sets the vertex type.  This can only be called once.  Repeated calls will except.
	 * 
	 * @param vertexType the type
	 */
	public void setVertexType(FGVertexType vertexType);

	public Address getVertexAddress();

	/**
	 * Returns true if this vertex is considered an entry.  Normally, a vertex is considered
	 * an entry if it is a source, with no incoming edges.  This vertex can be considered an
	 * entry even if it has incoming edges, such as when another function directly calls the
	 * code block associated with this vertex.
	 * 
	 * @return true if this vertex is an entry
	 */
	public boolean isEntry();

	public FlowType getFlowType();

	public AddressSetView getAddresses();

	public Program getProgram();

	public ListingModel getListingModel(Address address);

	public Color getDefaultBackgroundColor();

	public Color getBackgroundColor();

	public Color getSelectionColor();

	public void setBackgroundColor(Color color);

	public void clearColor();

	/**
	 * Signals to this vertex that it is associated with a group
	 * 
	 * @param groupInfo the new group info for this vertex; null if the vertex is no longer part
	 *        of a group 
	 */
	public void updateGroupAssociationStatus(GroupHistoryInfo groupInfo);

	/**
	 * The group info for this vertex if it is in a group; null if not in a group
	 * @return the group info or null
	 */
	public GroupHistoryInfo getGroupInfo();

	/**
	 * Returns true if this vertex is a member of an uncollapsed group
	 * @return true if this vertex is a member of an uncollapsed group
	 */
	public boolean isUncollapsedGroupMember();

	public String getTitle();

	public String getToolTipText(MouseEvent event);

	public JComponent getToolTipComponentForEdge(FGEdge edge);

	public JComponent getToolTipComponentForVertex();

	public boolean isDefaultBackgroundColor();

	public Rectangle getBounds();

	public boolean containsProgramLocation(ProgramLocation location);

	public boolean containsAddress(Address address);

	public void setProgramLocation(ProgramLocation location);

	public void setProgramSelection(ProgramSelection selection);

	public ProgramSelection getProgramSelection();

	/**
	 * Returns any selected text within the vertex that does not span multiple fields
	 * @return the text
	 */
	public String getTextSelection();

	public void setProgramHighlight(ProgramSelection highlight);

	public ProgramLocation getProgramLocation();

	public Rectangle getCursorBounds();

	/**
	 * Edits the label for the vertex.  This could be the label for the minimum address of the
	 * vertex's code block or this could be the text of the vertex's display (as it is for a 
	 * grouped vertex).
	 * 
	 * @param component the parent component of any shown dialogs
	 */
	public void editLabel(JComponent component);

	/**
	 * Returns true if the clicked component is or is inside of the header of the vertex
	 * 
	 * @param clickedComponent the clicked component
	 * @return true if the clicked component is or is inside of the header of the vertex
	 */
	public boolean isHeaderClick(Component clickedComponent);

	/**
	 * Signals that this vertex is being rendered such that it takes up the entire graph 
	 * window.  
	 *
	 * @return true if full-screen
	 */
	public boolean isFullScreenMode();

	/**
	 * Sets whether this vertex is in full-screen mode.  When in full-screen, a larger 
	 * view of the code block will be provided.  When not in full-screen, a condensed view
	 * of this vertex is provided. 
	 * 
	 * @param fullScreen true for full-screen
	 */
	public void setFullScreenMode(boolean fullScreen);

	/**
	 * Returns the full-screen view of this vertex. 
	 * @return the full-screen view
	 */
	public Component getMaximizedViewComponent();

	/**
	 * Signals to rebuild this vertex's data model.  This call will not do any real work 
	 * if the model is not 'dirty'.
	 */
	public void refreshModel();

	/**
	 * Triggers a refresh of the visual components of this vertex, such as the title.
	 */
	public void refreshDisplay();

	/**
	 * Refresh the vertex's display information if the given address is the vertex entry point
	 * @param address the addresses
	 */
	public void refreshDisplayForAddress(Address address);

	/**
	 * Tells this vertex whether it is showing.  This actually overrides the underlying 
	 * Java component's {@link JComponent#isShowing()} method in order to prevent it from
	 * showing tooltips (we manage tooltips ourselves).
	 * 
	 * <P>We have to set this to true painting, but then false when we are done (Java 
	 * components will not paint themselves if the are not showing). 
	 * 
	 * @param isShowing true if the component is showing
	 */
	public void setShowing(boolean isShowing);

	@Override
	public void dispose();

}
