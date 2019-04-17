/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.layout;

import java.awt.*;
import java.io.Serializable;

/**
  * Puts the first child of the given component in the middle of the component, both vertically
  * and horizontally.
  */
public class MiddleLayout implements LayoutManager, Serializable {
    
    @Override
	public void addLayoutComponent(String name, Component comp) {
        // nothing to do
	}
    
	@Override
	public void removeLayoutComponent(Component comp) {
	    // nothing to do
	}

    @Override
	public Dimension preferredLayoutSize(Container container) {
		Component[] components = container.getComponents();
        if ( components.length == 0 ) {
            return new Dimension(0, 0);
        }
        
        Component component = components[0];
        if ( component == null ) {
            return new Dimension(0, 0); // shouldn't happen
        }
		
		Dimension size = new Dimension(component.getPreferredSize());
		Insets insets = container.getInsets();
		size.height += insets.top + insets.bottom;
		size.width += insets.left + insets.right;		
		return size;
	}

    @Override
	public Dimension minimumLayoutSize(Container cont) {
		return preferredLayoutSize(cont);
	}

    @Override
	public void layoutContainer(Container container) {
        Component[] components = container.getComponents();
        if ( components.length == 0 ) {
            return;
        }
        
        Component component = components[0];
        if ( component == null ) {
            return; // shouldn't happen
        }
        
        component.setSize(component.getPreferredSize());
        Dimension size = component.getSize();
        Dimension containerSize = container.getSize();
        Insets insets = container.getInsets();
        containerSize.width -= insets.left + insets.right;
        containerSize.height -= insets.top + insets.bottom;
        int middleTop = (containerSize.height / 2) - (size.height / 2);
        int middleLeft = (containerSize.width / 2) - (size.width / 2);        
        middleLeft += insets.left;
        middleTop += insets.top;

        component.setBounds(middleLeft, middleTop, size.width, size.height);
	}
}
