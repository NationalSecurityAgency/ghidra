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
package datagraph.data.graph;

import java.awt.Component;
import java.awt.Shape;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import javax.swing.JComponent;

import datagraph.graph.explore.EgVertex;
import docking.action.DockingAction;
import ghidra.base.graph.CircleWithLabelVertexShapeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * A vertex that represents code in a data exploration graph. Currently, code vertices are
 * "dead end" vertices in the graph and cannot be explored further.
 */
public class CodeDegVertex extends DegVertex {

	private Instruction instruction;
	private CircleWithLabelVertexShapeProvider shapeProvider;

	/**
	 * Constructor
	 * @param controller the graph controller
	 * @param instruction the instruction that is reference from/to a data object in the graph.
	 * @param parent the source vertex (from what vertex did you explore to get here)
	 */
	public CodeDegVertex(DegController controller, Instruction instruction, DegVertex parent) {
		super(controller, parent);
		this.instruction = instruction;
		String label = getVertexLabel();

		this.shapeProvider = new CircleWithLabelVertexShapeProvider(label);
		shapeProvider.setTogglesVisible(false);

	}

	@Override
	public String getTitle() {
		return null;
	}

	@Override
	public int hashCode() {
		return instruction.hashCode();
	}

	@Override
	public DegVertexStatus refreshGraph(boolean checkDataTypes) {
		return DegVertexStatus.VALID;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CodeDegVertex other = (CodeDegVertex) obj;
		return instruction.equals(other.instruction);
	}

	private String getVertexLabel() {
		Address address = instruction.getAddress();
		Program program = instruction.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Function f = functionManager.getFunctionContaining(address);
		if (f != null) {
			String name = f.getName();
			if (!f.getEntryPoint().equals(address)) {
				name += " + " + address.subtract(f.getEntryPoint());
			}
			return name;
		}
		return address.toString();
	}

	@Override
	public void clearUserChangedLocation() {
		super.clearUserChangedLocation();
		controller.relayoutGraph();
	}

	@Override
	public String toString() {
		return "Instruction @ " + instruction.getAddress().toString();
	}

	@Override
	public Shape getCompactShape() {
		return shapeProvider.getCompactShape();
	}

	@Override
	public Shape getFullShape() {
		return shapeProvider.getFullShape();
	}

	@Override
	public JComponent getComponent() {
		return shapeProvider.getComponent();
	}

	@Override
	protected void addAction(DockingAction action) {
		//codeVertexPanel.addAction(action);
	}

	@Override
	public Address getAddress() {
		return instruction.getMinAddress();
	}

	@Override
	public void setSelected(boolean selected) {
		super.setSelected(selected);
		controller.navigateOut(instruction.getAddress(), null);
	}

	@Override
	public CodeUnit getCodeUnit() {
		return instruction;
	}

	@Override
	public boolean isGrabbable(Component component) {
		return true;
	}

	@Override
	protected Point2D getStartingEdgePoint(EgVertex end) {
		Point2D location = getLocation();
		return new Point2D.Double(location.getX(),
			location.getY() + shapeProvider.getCircleCenterYOffset());
	}

	@Override
	protected Point2D getEndingEdgePoint(EgVertex start) {
		Point2D location = getLocation();
		return new Point2D.Double(location.getX(),
			location.getY() + shapeProvider.getCircleCenterYOffset());
	}

	@Override
	protected boolean containsAddress(Address address) {
		return instruction.contains(address);
	}

	@Override
	public String getTooltip(MouseEvent e) {
		return null;
	}

	@Override
	public int compare(DegVertex o1, DegVertex o2) {
		return o1.getAddress().compareTo(o2.getAddress());
	}
}
