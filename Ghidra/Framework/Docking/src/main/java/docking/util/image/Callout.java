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

import generic.theme.GThemeDefaults.Colors.Palette;
import generic.util.image.ImageUtils;
import generic.util.image.ImageUtils.Padding;
import ghidra.util.Msg;

public class Callout {

	private static final Color CALLOUT_SHAPE_COLOR = Palette.getColor("yellowgreen"); //Palette.getColor("palegreen");
	private static final int CALLOUT_BORDER_PADDING = 20;

	public Image createCalloutOnImage(Image image, CalloutInfo calloutInfo) {
		try {
			return doCreateCalloutOnImage(image, calloutInfo);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception creating callout image", e);
			throw e;
		}
	}

	private Image doCreateCalloutOnImage(Image image, CalloutInfo calloutInfo) {

		//
		// This code creates a 'call out' image, which is a round, zoomed image of an area
		// in the given image, as chosen by the client.  Further, a cone shape will extend
		// from the client's chosen location to the callout image we create here.
		//

		//
		// Callout Size (this is the small image that will be in the center of the overall callout
		// shape)
		//
		Rectangle clientBounds = calloutInfo.getBounds();
		Dimension clientShapeSize = clientBounds.getSize();
		int newHeight = clientShapeSize.height * 6;
		int calloutHeight = newHeight;
		int calloutWidth = calloutHeight; // square

		//
		// Callout Offset (from original shape that is being magnified).  This is the location 
		// (relative to the original component) of the callout image (not the full shape; the round
		// magnified image).  So, if the x offset is 10, then the callout image would start 10 pixels
		// to the right of the component.
		//
		double offsetX = calloutWidth * 1.5;
		double offsetY = calloutHeight * 2;

		// only pad if the callout leaves the bounds of the parent image
		int topPadding = 0;
		Point clientLocation = clientBounds.getLocation();

		//
		// Callout Bounds
		//
		// set the callout location offset from the client area and angle it as well
		double theta = Math.toRadians(45);
		int calloutX = (int) (clientLocation.x + (Math.cos(theta) * offsetX));
		int calloutY = (int) (clientLocation.y - (Math.sin(theta) * offsetY));
		Rectangle calloutShapeBounds =
			new Rectangle(calloutX, calloutY, calloutWidth, calloutHeight);

		//
		// Full Callout Shape Bounds (this does not include the drop-shadow)
		//
		Rectangle calloutBounds = clientBounds.union(calloutShapeBounds);
		BufferedImage calloutImage =
			createCalloutImage(calloutInfo, calloutShapeBounds, calloutBounds);

		calloutInfo.moveToDestination(calloutBounds);

		Point calloutLocation = calloutBounds.getLocation();
		int top = calloutLocation.y - CALLOUT_BORDER_PADDING;
		if (top < 0) {
			// the callout would be drawn off the top of the image; pad the image
			topPadding = -top;
		}

		//
		// The drop shadow size is used also to control the offset of the shadow.  The shadow is 
		// twice as big as the callout we will paint.  The shadow will be painted first, with the
		// callout image on top.
		// 
		DropShadow dropShadow = new DropShadow();
		Image shadow = dropShadow.createDropShadow(calloutImage, 40);

		//
		// Create our final image and draw into it the callout image and its shadow
		//		

		Padding padding = createImagePadding(image, shadow, calloutBounds, topPadding);
		Color bg = Palette.WHITE;
		Image paddedImage = ImageUtils.padImage(image, bg, padding);
		Graphics g = paddedImage.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		// Get the final location that may have been updated if we padded the image
		int paddedX = calloutLocation.x += padding.left();
		int paddedY = calloutLocation.y += padding.top();
		Point finalLocation = new Point(paddedX, paddedY);
		g2d.drawImage(shadow, finalLocation.x, finalLocation.y, null);
		g2d.drawImage(calloutImage, finalLocation.x, finalLocation.y, null);

		//
		// Debug
		//
//		g2d.setColor(Palette.RED);
//		Rectangle calloutImageBounds = new Rectangle(finalLocation.x, finalLocation.y,
//			calloutImage.getWidth(), calloutImage.getHeight());
//		g2d.draw(calloutImageBounds);
//
//		g2d.setColor(Palette.ORANGE);
//		Rectangle destCalloutBounds = new Rectangle(calloutShapeBounds);
//		calloutInfo.moveToImage(destCalloutBounds, padding);
//		destCalloutBounds.setLocation(destCalloutBounds.getLocation());
//		g2d.draw(destCalloutBounds);
//
//		g2d.setColor(Palette.BLUE);
//		Rectangle movedClient = new Rectangle(calloutInfo.getBounds());
//		calloutInfo.moveToImage(movedClient, padding);
//		g2d.draw(movedClient);

		return paddedImage;
	}

	private Padding createImagePadding(Image fullImage, Image shadow, Rectangle calloutOnlyBounds,
			int topPad) {
		Point calloutLocation = calloutOnlyBounds.getLocation();
		int sw = shadow.getWidth(null);
		int sh = shadow.getHeight(null);
		Rectangle shadowBounds = new Rectangle(calloutLocation.x, calloutLocation.y, sw, sh);
		Rectangle combinedBounds = calloutOnlyBounds.union(shadowBounds);
		int endX = calloutLocation.x + combinedBounds.width;
		int overlap = endX - fullImage.getWidth(null);
		int rightPad = 0;
		if (overlap > 0) {
			rightPad = overlap + CALLOUT_BORDER_PADDING;
		}

		int endY = calloutLocation.y + combinedBounds.height;
		int bottomPad = 0;
		overlap = endY - fullImage.getHeight(null);
		if (overlap > 0) {
			bottomPad = overlap;
		}

		int leftPad = 0;
		return new Padding(topPad, leftPad, rightPad, bottomPad);
	}

	private BufferedImage createCalloutImage(CalloutInfo calloutInfo,
			Rectangle calloutShapeBounds, Rectangle fullBounds) {

		// 
		// The client shape will be to the left of the callout.  The client shape and the callout
		// bounds together are the full shape.
		// 
		BufferedImage calloutImage =
			new BufferedImage(fullBounds.width, fullBounds.height, BufferedImage.TYPE_INT_ARGB);
		Graphics2D cg = (Graphics2D) calloutImage.getGraphics();
		cg.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		//
		// Make relative our two shapes--the component shape and the callout shape
		//
		Point calloutOrigin = fullBounds.getLocation(); // the shape is relative to the full bounds
		int sx = calloutShapeBounds.x - calloutOrigin.x;
		int sy = calloutShapeBounds.y - calloutOrigin.y;

		Ellipse2D calloutShape =
			new Ellipse2D.Double(sx, sy, calloutShapeBounds.width, calloutShapeBounds.height);

		Rectangle clientBounds = calloutInfo.getBounds();
		Point clientLocation = clientBounds.getLocation();
		int cx = clientLocation.x - calloutOrigin.x;
		int cy = clientLocation.y - calloutOrigin.y;
		Dimension clientSize = clientBounds.getSize();

// TODO this shows how to correctly account for scaling in the Function Graph
//		Dimension cSize2 = new Dimension(cSize);
//		double scale = .5d;
//		cSize2.width *= scale;
//		cSize2.height *= scale;

		Rectangle componentShape = new Rectangle(new Point(cx, cy), clientSize);
		paintCalloutArrow(cg, componentShape, calloutShape.getBounds());
		paintCalloutCircularImage(cg, calloutInfo, calloutShape);

		cg.dispose();
		return calloutImage;
	}

	private void paintCalloutCircularImage(Graphics2D g, CalloutInfo calloutInfo,
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

	private void paintCalloutArrow(Graphics2D g2d, Rectangle componentShape,
			Rectangle calloutShape) {

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
			CalloutInfo calloutInfo, RectangularShape imageShape) {

		Rectangle r = new Rectangle(calloutInfo.getBounds());
		calloutInfo.moveToScreen(r);

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
			// shouldn't happen
			throw new RuntimeException("Unable to create a Robot for capturing the screen", e);
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
		g.setColor(Palette.WHITE);

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
