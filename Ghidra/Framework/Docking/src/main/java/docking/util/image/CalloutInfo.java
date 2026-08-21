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

import generic.util.image.ImageUtils.Padding;

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
public class CalloutInfo {

	private Rectangle clientShape;
	private Component source;
	private Component destination;

	private double magnification = 2.0;

	/**
	 * Constructor for the destination component, the source component and the area that is to be
	 * captured.  This constructor will call out the entire shape of the given source component.
	 * <p>
	 * The destination component needs to be the item that was captured in the screenshot.  If you
	 * captured a window, then pass that window as the destination.  If you captured a sub-component
	 * of a window, then pass that sub-component as the destination.
	 * 
	 * @param destinationComponent the component over which the image will be painted
	 * @param sourceComponent the component that contains the area that will be called out
	 */
	public CalloutInfo(Component destinationComponent, Component sourceComponent) {
		this(destinationComponent, sourceComponent, sourceComponent.getBounds());
	}

	/**
	 * Constructor for the destination component, the source component and the area that is to be
	 * captured.
	 * <p>
	 * The destination component needs to be the item that was captured in the screenshot.  If you
	 * captured a window, then pass that window as the destination.  If you captured a sub-component
	 * of a window, then pass that sub-component as the destination.
	 * 
	 * @param destinationComponent the component over which the image will be painted
	 * @param sourceComponent the component that contains the area that will be called out
	 * @param clientShape the shape that will be called out
	 */
	public CalloutInfo(Component destinationComponent, Component sourceComponent,
			Rectangle clientShape) {

		this.destination = destinationComponent;
		this.source = sourceComponent;
		this.clientShape = clientShape;
	}

	public void setMagnification(double magnification) {
		this.magnification = magnification;
	}

	public double getMagnification() {
		return magnification;
	}

	/**
	 * Moves the given rectangle to the image destination space.   Clients use this to create new 
	 * shapes using the <B>client space</B> and then move them to the image destination space.
	 * @param r the rectangle
	 * @param padding any padding around the destination image
	 */
	public void moveToImage(Rectangle r, Padding padding) {
		moveToDestination(r);
		r.x += padding.left();
		r.y += padding.top();
	}

	/**
	 * Moves the given rectangle to the image destination space.   Clients use this to create new 
	 * shapes using the <B>client space</B>.  This destination space is not the same as the final 
	 * image that will get created.
	 * @param r the rectangle
	 */
	public void moveToDestination(Rectangle r) {
		Point oldPoint = r.getLocation();
		Point newPoint = SwingUtilities.convertPoint(source.getParent(), oldPoint, destination);
		r.setLocation(newPoint);
	}

	/**
	* Moves the given rectangle to screen space. Clients use this to create new shapes using the
	* <B>client space</B> and then move them to the image destination space.
	* @param r the rectangle
	*/
	public void moveToScreen(Rectangle r) {
		Point p = r.getLocation();
		SwingUtilities.convertPointToScreen(p, source.getParent());
		r.setLocation(p);
	}

	public Rectangle getBounds() {
		return new Rectangle(clientShape);
	}
}
