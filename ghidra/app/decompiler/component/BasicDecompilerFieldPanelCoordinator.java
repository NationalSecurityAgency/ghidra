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
package ghidra.app.decompiler.component;

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * A basic coordinator that locks two decompiler panels together at the first line so that 
 * scrolling one side also scrolls the other. It also allows the cursor locations to track 
 * together based on the line number or to move independent of each other.
 */
public class BasicDecompilerFieldPanelCoordinator extends DualDecompilerFieldPanelCoordinator {

	private DecompilerCodeComparisonPanel<BasicDecompilerFieldPanelCoordinator> dualDecompilerPanel;
	private boolean syncLineLocation;

	/**
	 * Constructs a dual decompiler coordinator that scrolls the two panels together so that 
	 * they are locked together at the first line.
	 * @param dualDecompilerPanel the dual decompiler panel being controlled by this coordinator
	 * @param syncLineLocation true means synchronize the cursors in the two decompiler panels 
	 * to the same line number and offset if possible. false means the the cursors move 
	 * independently of each other.
	 */
	public BasicDecompilerFieldPanelCoordinator(
			BasicDecompilerCodeComparisonPanel dualDecompilerPanel, boolean syncLineLocation) {
		super(dualDecompilerPanel);
		this.dualDecompilerPanel = dualDecompilerPanel;
		this.syncLineLocation = syncLineLocation;
	}

	@Override
	public void leftLocationChanged(ProgramLocation leftProgramLocation) {

		if (syncLineLocation) {
			CDisplayPanel focusedDecompilerPanel = dualDecompilerPanel.getFocusedDecompilerPanel();

			CDisplayPanel leftPanel = dualDecompilerPanel.getLeftPanel();
			CDisplayPanel rightPanel = dualDecompilerPanel.getRightPanel();
			if (focusedDecompilerPanel != leftPanel) {
				return; // Don't respond to location change from synchronizing left and right.
			}

			DecompilerPanel leftDecompilerPanel = leftPanel.getDecompilerPanel();
			DecompilerPanel rightDecompilerPanel = rightPanel.getDecompilerPanel();

			FieldLocation leftFieldLocation = leftDecompilerPanel.getCursorPosition();
			rightDecompilerPanel.setCursorPosition(leftFieldLocation);
		}
	}

	@Override
	public void rightLocationChanged(ProgramLocation rightProgramLocation) {

		if (syncLineLocation) {
			CDisplayPanel focusedDecompilerPanel = dualDecompilerPanel.getFocusedDecompilerPanel();

			CDisplayPanel leftPanel = dualDecompilerPanel.getLeftPanel();
			CDisplayPanel rightPanel = dualDecompilerPanel.getRightPanel();
			if (focusedDecompilerPanel != rightPanel) {
				return; // Don't respond to location change from synchronizing left and right.
			}

			DecompilerPanel leftDecompilerPanel = leftPanel.getDecompilerPanel();
			DecompilerPanel rightDecompilerPanel = rightPanel.getDecompilerPanel();

			FieldLocation rightFieldLocation = rightDecompilerPanel.getCursorPosition();
			leftDecompilerPanel.setCursorPosition(rightFieldLocation);
		}
	}

}
