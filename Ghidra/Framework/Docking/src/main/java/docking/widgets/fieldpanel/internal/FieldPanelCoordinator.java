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
package docking.widgets.fieldpanel.internal;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.listener.ViewListener;
import docking.widgets.fieldpanel.support.ViewerPosition;


/**
 * Coordinates the scrolling of a set of field panels by sharing bound scroll models.
 */
public class FieldPanelCoordinator implements ViewListener {
	FieldPanel[] panels;
	boolean valuesChanging;

	/**
	 * Constructs a new FieldPanelCoordinatro to synchronize the scrolling of the given field panels.
	 * @param panels the array of panels to synchronize.
	 */
	public FieldPanelCoordinator(FieldPanel[] panels) {
		this.panels = new FieldPanel[panels.length];
		System.arraycopy(panels, 0, this.panels, 0, panels.length);
		for(int i=0;i<panels.length;i++) {
			addListeners(panels[i]);
		}
	}
	/**
	 * Cleans up resources.
	 */
	public void dispose() {
		for(int i=0;i<panels.length;i++) {
			removeListeners(panels[i]);
		}
		panels = null;
	}

	/**
	 * Adds the given field panel to the list of panels to synchronize.
	 * @param fp the field panel to add.
	 */
	public void add(FieldPanel fp) {
		addListeners(fp);
		FieldPanel[] newPanels = new FieldPanel[panels.length+1];
		System.arraycopy(panels, 0, newPanels, 0, panels.length);
		newPanels[panels.length] = fp;
		panels = newPanels;
		ViewerPosition vp = fp.getViewerPosition();
		viewChanged(fp, vp.getIndex(), vp.getXOffset(), vp.getYOffset());
	}
	
	/**
	 * Removes the given field panel from the list to be synchronized.
	 */
	public void remove(FieldPanel fp) {
		removeListeners(fp);
		FieldPanel[] newPanels = new FieldPanel[panels.length-1];
		int j = 0;
		for(int i=0;i<panels.length;i++) {
			if (panels[i] != fp) {
				newPanels[j++] = panels[i];
			}
		}
		panels = newPanels;
	}
	
	@Override
	public void viewChanged(FieldPanel fp, BigInteger index, int xPos, int yPos) {
		if (valuesChanging) return;
		valuesChanging = true;
		try {
			for(int i=0;i<panels.length;i++) {
				if (panels[i] != fp) {
					panels[i].setViewerPosition(index, xPos, yPos);
				}
			}
		}finally {
			valuesChanging = false;		
		}
	}

	private void addListeners(FieldPanel fp) {
		fp.addViewListener(this);
	
	
	}
	private void removeListeners(FieldPanel fp) {
		fp.removeViewListener(this);
	
	}


}
