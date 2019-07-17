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
import java.awt.geom.Ellipse2D;
import java.awt.geom.RectangularShape;
import java.awt.image.BufferedImage;
import java.awt.image.VolatileImage;

import generic.util.image.ImageUtils;

public class Callout {

	private static final Color CALLOUT_SHAPE_COLOR = new Color(0xB5, 0xDE, 0x2F);
	private static final int CALLOUT_BORDER_PADDING = 20;

	public Image createCallout(CalloutComponentInfo calloutInfo) {

		double distanceFactor = 1.15;

		//
		// Callout Size
		//
		Dimension cSize = calloutInfo.getSize();
		int newHeight = cSize.height * 4;
		int calloutHeight = newHeight;
		int calloutWidth = calloutHeight; // square

		//
		// Callout Distance (from original component)
		//
		double xDistance = calloutWidth * distanceFactor * .80;
		double yDistance = calloutHeight * distanceFactor * distanceFactor;

		// only pad if the callout leaves the bounds of the parent image
		int padding = 0;
		Rectangle cBounds = calloutInfo.getBounds();
		Point cLoc = cBounds.getLocation();
		if (yDistance > cLoc.y) {
			// need some padding!
			padding = (int) Math.round(calloutHeight * distanceFactor);
			cLoc.y += padding;
			cBounds.setLocation(cLoc.x, cLoc.y); // move y down by the padding
		}

		boolean goLeft = false;

// TODO for now, always go right
//		Rectangle pBounds = parentComponent.getBounds();
//		double center = pBounds.getCenterX();
//		if (cLoc.x > center) {
//			goLeft = true; // callout is on the right of center--go to the left
//		}

		//
		// Callout Bounds
		//
		int calloutX = (int) (cLoc.x + (goLeft ? -(xDistance + calloutWidth) : xDistance));
		int calloutY = (int) (cLoc.y + -yDistance);
		int backgroundWidth = calloutWidth;
		int backgroundHeight = backgroundWidth; // square
		Rectangle calloutBounds =
			new Rectangle(calloutX, calloutY, backgroundWidth, backgroundHeight);

		//
		// Full Callout Shape Bounds
		//
		Rectangle fullBounds = cBounds.union(calloutBounds);
		BufferedImage calloutImage =
			createCalloutImage(calloutInfo, cLoc, calloutBounds, fullBounds);

//		DropShadow dropShadow = new DropShadow();
//		Image shadow = dropShadow.createDrowShadow(calloutImage, 40);

		//
		// Create our final image and draw into it the callout image and its shadow
		//

		return calloutImage;

//		int width = Math.max(shadow.getWidth(null), calloutImage.getWidth());
//		int height = Math.max(shadow.getHeight(null), calloutImage.getHeight());
//
//		BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
//
//		Graphics g = image.getGraphics();
//		Graphics2D g2d = (Graphics2D) g;
//		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
//
//		Point imageLoc = calloutInfo.convertPointToParent(fullBounds.getLocation());
//		g2d.drawImage(shadow, imageLoc.x, imageLoc.y, null);
//		g2d.drawImage(calloutImage, imageLoc.x, imageLoc.y, null);

		//
		//
		//
		//
		// Debug
		//
//		g2d.setColor(Color.RED);
//		g2d.draw(fullBounds);
//
//		g2d.setColor(Color.CYAN);
//		g2d.draw(calloutBounds);
//
//		g2d.setColor(Color.BLUE);
//		g2d.draw(cBounds);

//		return image;
	}

	public Image createCalloutOnImage(Image image, CalloutComponentInfo calloutInfo) {

		//
		// This code creates a 'call out' image, which is a round, zoomed image of an area
		// in the given image, as chosen by the client.  Further, a cone shape will extend 
		// from the client's chosen location to the callout image we create here.
		//

		//
		// Callout Size
		//
		Dimension cSize = calloutInfo.getSize();
		int newHeight = cSize.height * 6;
		int calloutHeight = newHeight;
		int calloutWidth = calloutHeight; // square

		//
		// Callout Distance (from original component).  This is the location (relative to 
		// the original component) of the callout image (not the full shape).  So, if the
		// x distance was 10, then the callout image would start 10 pixels to the right of 
		// the component.
		//
		double distanceX = calloutWidth * 1.5;
		double distanceY = calloutHeight * 2;

		// only pad if the callout leaves the bounds of the parent image
		int topPadding = 0;
		Rectangle componentBounds = calloutInfo.getBounds();
		Point componentLocation = componentBounds.getLocation();
		Point imageComponentLocation = calloutInfo.convertPointToParent(componentLocation);

		int calloutImageY = imageComponentLocation.y - ((int) distanceY);
		if (calloutImageY < 0) {

			// the callout would be drawn off the top of the image; pad the image
			topPadding = Math.abs(calloutImageY) + CALLOUT_BORDER_PADDING;

			// Also, since we have made the image bigger, we have to the component bounds, as
			// the callout image uses these bounds to know where to draw the callout.  If we
			// don't move them, then the padding will cause the callout to be drawn higher 
			// by the amount of the padding.
			componentLocation.y += topPadding;
			componentBounds.setLocation(componentLocation.x, componentLocation.y);
		}

		//
		// Callout Bounds
		//
		// angle the callout
		double theta = Math.toRadians(45);
		int calloutX = (int) (componentLocation.x + (Math.cos(theta) * distanceX));
		int calloutY = (int) (componentLocation.y - (Math.sin(theta) * distanceY));

		int backgroundWidth = calloutWidth;
		int backgroundHeight = backgroundWidth; // square
		Rectangle calloutBounds =
			new Rectangle(calloutX, calloutY, backgroundWidth, backgroundHeight);

		//
		// Full Callout Shape Bounds (this does not include the drop-shadow)
		//
		Rectangle calloutDrawingArea = componentBounds.union(calloutBounds);
		BufferedImage calloutImage =
			createCalloutImage(calloutInfo, componentLocation, calloutBounds, calloutDrawingArea);

		DropShadow dropShadow = new DropShadow();
		Image shadow = dropShadow.createDrowShadow(calloutImage, 40);

		//
		// Create our final image and draw into it the callout image and its shadow
		//
		Point calloutImageLoc = calloutInfo.convertPointToParent(calloutDrawingArea.getLocation());
		calloutDrawingArea.setLocation(calloutImageLoc);

		Rectangle dropShadowBounds = new Rectangle(calloutImageLoc.x, calloutImageLoc.y,
			shadow.getWidth(null), shadow.getHeight(null));
		Rectangle completeBounds = calloutDrawingArea.union(dropShadowBounds);
		int fullBoundsXEndpoint = calloutImageLoc.x + completeBounds.width;
		int overlap = fullBoundsXEndpoint - image.getWidth(null);
		int rightPadding = 0;
		if (overlap > 0) {
			rightPadding = overlap + CALLOUT_BORDER_PADDING;
		}

		int fullBoundsYEndpoint = calloutImageLoc.y + completeBounds.height;
		int bottomPadding = 0;
		overlap = fullBoundsYEndpoint - image.getHeight(null);
		if (overlap > 0) {
			bottomPadding = overlap;
		}

		image = ImageUtils.padImage(image, Color.WHITE, topPadding, 0, rightPadding, bottomPadding);
		Graphics g = image.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		g2d.drawImage(shadow, calloutImageLoc.x, calloutImageLoc.y, null);
		g2d.drawImage(calloutImage, calloutImageLoc.x, calloutImageLoc.y, null);

		//
		//
		//
		//
		// Debug
		//
//		g2d.setColor(Color.RED);
//		g2d.draw(fullBounds);
//
//		g2d.setColor(Color.CYAN);
//		g2d.draw(calloutBounds);
//
//		g2d.setColor(Color.BLUE);
//		g2d.draw(componentBounds);
//
//		g2d.setColor(Color.MAGENTA);
//		g2d.draw(completeBounds);
//
//		g2d.setColor(Color.GRAY);
//		g2d.draw(dropShadowBounds);
//
//		Point cLocation = componentBounds.getLocation();
//		Point convertedCLocation = calloutInfo.convertPointToParent(cLocation);
//		g2d.setColor(Color.PINK);
//		componentBounds.setLocation(convertedCLocation);
//		g2d.draw(componentBounds);
//
//		Point convertedFBLocation = calloutInfo.convertPointToParent(fullBounds.getLocation());
//		fullBounds.setLocation(convertedFBLocation);
//		g2d.setColor(Color.ORANGE);
//		g2d.draw(fullBounds);

		return image;
	}

	private BufferedImage createCalloutImage(CalloutComponentInfo calloutInfo, Point cLoc,
			Rectangle calloutBounds, Rectangle fullBounds) {
		BufferedImage calloutImage =
			new BufferedImage(fullBounds.width, fullBounds.height, BufferedImage.TYPE_INT_ARGB);
		Graphics2D cg = (Graphics2D) calloutImage.getGraphics();
		cg.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		//
		// Make relative our two shapes--the component shape and the callout shape
		//
		Point calloutOrigin = fullBounds.getLocation(); // the shape is relative to the full bounds
		int sx = calloutBounds.x - calloutOrigin.x;
		int sy = calloutBounds.y - calloutOrigin.y;
		Ellipse2D calloutShape =
			new Ellipse2D.Double(sx, sy, calloutBounds.width, calloutBounds.height);

		int cx = cLoc.x - calloutOrigin.x;
		int cy = cLoc.y - calloutOrigin.y;
		Dimension cSize = calloutInfo.getSize();

// TODO this shows how to correctly account for scaling in the Function Graph		
//		Dimension cSize2 = new Dimension(cSize);
//		double scale = .5d;
//		cSize2.width *= scale;
//		cSize2.height *= scale;
		Rectangle componentShape = new Rectangle(new Point(cx, cy), cSize);

		paintCalloutArrow(cg, componentShape, calloutShape);
		paintCalloutCircularImage(cg, calloutInfo, calloutShape);

		cg.dispose();
		return calloutImage;
	}

	private void paintCalloutCircularImage(Graphics2D g, CalloutComponentInfo calloutInfo,
			RectangularShape shape) {

		//
		// First draw the background circle that will sit beneath the image, to create a 
		// ring around the image
		//
		g.setColor(CALLOUT_SHAPE_COLOR);
		g.fill(shape);

		// 
		// Now, make the image a bit smaller, so that the background is a ring around the image
		//
		int offset = 3;
		Rectangle sr = shape.getBounds(); // shape rectangle
		Rectangle ir = new Rectangle(); // image rectangle
		ir.x = sr.x + offset;
		ir.y = sr.y + offset;
		ir.width = sr.width - (2 * offset);
		ir.height = sr.height - (2 * offset);

		shape.setFrame(ir); // change the size for the image

		Dimension imageSize = ir.getSize();
		Image foregroundImage =
			createMagnifiedImage(g.getDeviceConfiguration(), imageSize, calloutInfo, shape);

		shape.setFrame(sr); // restore

		g.drawImage(foregroundImage, ir.x, ir.y, null);
	}

	private void paintCalloutArrow(Graphics2D g2d, RectangularShape componentShape,
			RectangularShape calloutShape) {

		Rectangle cr = componentShape.getBounds();
		Rectangle sr = calloutShape.getBounds();
		Point p1 = new Point((int) cr.getCenterX(), (int) cr.getCenterY());
		Point p2 = new Point(sr.x + (sr.width / 2), sr.y + (sr.height / 2));

		// 
		// Calculate the tangents to the callout circle		
		//
		int radius = sr.width / 2;
		int dx = p2.x - p1.x;
		int dy = p2.y - p1.y;
		double distance = Math.sqrt(dx * dx + dy * dy);
		double alpha = Math.asin(radius / distance);
		double beta = Math.atan2(dy, dx);
		double theta = beta - alpha;
		double x = radius * Math.sin(theta) + p2.x;
		double y = radius * -Math.cos(theta) + p2.y;
		Point tangentA = new Point((int) Math.round(x), (int) Math.round(y));

		theta = beta + alpha;
		x = radius * -Math.sin(theta) + p2.x;
		y = radius * Math.cos(theta) + p2.y;
		Point tangentB = new Point((int) Math.round(x), (int) Math.round(y));

		g2d.setColor(CALLOUT_SHAPE_COLOR);

		Polygon p = new Polygon();
		p.addPoint(p1.x, p1.y);
		p.addPoint(tangentA.x, tangentA.y);
		p.addPoint(tangentB.x, tangentB.y);
		g2d.fillPolygon(p);
	}

	private Image createMagnifiedImage(GraphicsConfiguration gc, Dimension imageSize,
			CalloutComponentInfo calloutInfo, RectangularShape imageShape) {

		Dimension componentSize = calloutInfo.getSize();
		Point componentScreenLocation = calloutInfo.getLocationOnScreen();

		Rectangle r = new Rectangle(componentScreenLocation, componentSize);

		int offset = 100;
		r.x -= offset;
		r.y -= offset;
		r.width += 2 * offset;
		r.height += 2 * offset;

		Image compImage = null;
		try {
			Robot robot = new Robot();
			compImage = robot.createScreenCapture(r);
		}
		catch (AWTException e) {
			throw new RuntimeException("boom", e);
		}

		double magnification = calloutInfo.getMagnification();
		int newWidth = (int) (compImage.getWidth(null) * magnification);
		int newHeight = (int) (compImage.getHeight(null) * magnification);
		compImage = ImageUtils.createScaledImage(compImage, newWidth, newHeight, 0);

		Rectangle bounds = imageShape.getBounds();
		VolatileImage image =
			gc.createCompatibleVolatileImage(bounds.width, bounds.height, Transparency.TRANSLUCENT);
		Graphics2D g = (Graphics2D) image.getGraphics();

		// update all pixels to have 0 alpha
		g.setComposite(AlphaComposite.Clear);

		// update the shape to be relative to the new image's origin
		Rectangle relativeFrame = new Rectangle(new Point(0, 0), bounds.getSize());
		imageShape.setFrame(relativeFrame);

		g.fill(relativeFrame);

		// render the clip shape into the image
		g.setComposite(AlphaComposite.Src);
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.setColor(Color.WHITE);

		g.fill(imageShape);

		imageShape.setFrame(bounds); // restore

		// Using ScrAtop uses the alpha value as a coverage for each pixel stored in
		// the destination.  For the areas outside the clip shape, the destination alpha will
		// be zero, so nothing is rendered in those areas.
		g.setComposite(AlphaComposite.SrcAtop);

		int cw = compImage.getWidth(null);
		int ch = compImage.getHeight(null);
		int x = -((cw / 2) - (bounds.width / 2));
		int y = -((ch / 2) - (bounds.height / 2));

		g.drawImage(compImage, x, y, cw, ch, null);

		g.dispose();

		return image;
	}
}
