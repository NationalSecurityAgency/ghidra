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
package ghidra.graph.viewer.popup;

import java.awt.event.MouseEvent;

import javax.swing.JComponent;

/** 
 * Basic container object that knows how to generate tooltips
 * 
 * @param <T> the type of object for which to create a tooltip
 */
public abstract class ToolTipInfo<T> {

	protected final MouseEvent event;
	protected final T graphObject;
	private JComponent tooltipComponent;

	public ToolTipInfo(MouseEvent event, T t) {
		this.event = event;
		this.graphObject = t;
		tooltipComponent = createToolTipComponent();
	}

	/**
	 * Creates a tool tip component 
	 * @return the tool tip component
	 */
	protected abstract JComponent createToolTipComponent();

	/**
	 * Signals for the implementation to emphasis the original graph object passed to this info
	 */
	protected abstract void emphasize();

	/**
	 * Signals for the implementation to turn off emphasis
	 */
	protected abstract void deEmphasize();

	/**
	 * Returns the mouse event from this tool tip info
	 * @return the mouse event from this tool tip info
	 */
	MouseEvent getMouseEvent() {
		return event;
	}

	/**
	 * Returns the tool tip component created by this info
	 * @return the tool tip component created by this info
	 */
	JComponent getToolTipComponent() {
		return tooltipComponent;
	}
}
