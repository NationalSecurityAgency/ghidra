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
package docking.util.image;

import java.awt.*;

import javax.swing.SwingUtilities;

/**
 * An object that describes a component to be 'called-out'.  A callout is a way to 
 * emphasize a widget (usually this is only needed for small GUI elements, like an action or
 * icon).
 * 
 * <P>The given component info is used to render a magnified image of the given component 
 * onto another image.  For this to work, the rendering engine will need to know how to 
 * translate the component's location to that of the image space onto which the callout 
 * will be drawn.  This is the purpose of requiring the 'destination component'.  That 
 * component provides the bounds that will be used to move the component's relative position
 * (which is relative to the components parent).  
 */
public class CalloutComponentInfo {

	Point locationOnScreen;
	Point relativeLocation;
	Dimension size;

	Component component;
	Component destinationComponent;

	double magnification = 2.0;

	public CalloutComponentInfo(Component destinationComponent, Component component) {
		this(destinationComponent, component, component.getLocationOnScreen(),
			component.getLocation(), component.getSize());
	}

	public CalloutComponentInfo(Component destinationComponent, Component component,
			Point locationOnScreen, Point relativeLocation, Dimension size) {

		this.destinationComponent = destinationComponent;
		this.component = component;
		this.locationOnScreen = locationOnScreen;
		this.relativeLocation = relativeLocation;
		this.size = size;
	}

	public Point convertPointToParent(Point location) {
		return SwingUtilities.convertPoint(component.getParent(), location, destinationComponent);
	}

	public void setMagnification(double magnification) {
		this.magnification = magnification;
	}

	Component getComponent() {
		return component;
	}

	/**
	 * Returns the on-screen location of the component.  This is used for screen capture, which
	 * means if you move the component after this info has been created, this location will 
	 * be outdated.
	 *  
	 * @return the location
	 */
	Point getLocationOnScreen() {
		return locationOnScreen;
	}

	/**
	 * The size of the component we will be calling out
	 * 
	 * @return the size
	 */
	Dimension getSize() {
		return size;
	}

	Rectangle getBounds() {
		return new Rectangle(relativeLocation, size);
	}

	double getMagnification() {
		return magnification;
	}
}
