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
package ghidra.docking.util.painting;

import java.awt.*;
import java.awt.image.*;

import javax.swing.RepaintManager;

import ghidra.util.Msg;
import sun.awt.image.SurfaceManager;

/**
 * A repaint manager that can be plugged-in to Java's {@link RepaintManager} in order to 
 * change how we paint colors.
 * 
 * @see Graphics2D
 */
public class GRepaintManager extends RepaintManager {

	private VolatileImageWrapper imageWrapper = new VolatileImageWrapper();

	@Override
	public Image getVolatileOffscreenBuffer(Component c, int proposedWidth, int proposedHeight) {
		Image image = super.getVolatileOffscreenBuffer(c, proposedWidth, proposedHeight);

		if (!(image instanceof VolatileImage)) {
			Msg.debug(this,
				"Cannot install Graphics2D color inverter.  Non-volatile image found: " +
					image.getClass().getName());
			return image;
		}

		imageWrapper.setImage((VolatileImage) image);
		return imageWrapper;
	}

	private class VolatileImageWrapper extends VolatileImage {

		private Graphics2DWrapper wrapper = new Graphics2DWrapper();
		private VolatileImage image = this;

		void setImage(VolatileImage image) {
			this.image = image;
			SurfaceManager manager = SurfaceManager.getManager(image);
			SurfaceManager.setManager(this, manager);
		}

		@Override
		public Graphics getGraphics() {
			Graphics g = image.getGraphics();
			wrapper.setDelegate((Graphics2D) g);
			return wrapper;
		}

		@Override
		public BufferedImage getSnapshot() {
			return image.getSnapshot();
		}

		@Override
		public int getWidth() {
			return image.getWidth();
		}

		@Override
		public int getHeight() {
			return image.getHeight();
		}

		@Override
		public Graphics2D createGraphics() {
			return image.createGraphics();
		}

		@Override
		public int validate(GraphicsConfiguration gc) {
			return image.validate(gc);
		}

		@Override
		public boolean contentsLost() {
			return image.contentsLost();
		}

		@Override
		public ImageCapabilities getCapabilities() {
			return image.getCapabilities();
		}

		@Override
		public int getTransparency() {
			if (image == null) {
				return super.getTransparency();
			}
			return image.getTransparency();
		}

		@Override
		public int getWidth(ImageObserver observer) {
			return image.getWidth(observer);
		}

		@Override
		public int hashCode() {
			return image.hashCode();
		}

		@Override
		public int getHeight(ImageObserver observer) {
			return image.getHeight(observer);
		}

		@Override
		public ImageProducer getSource() {
			return image.getSource();
		}

		@Override
		public boolean equals(Object obj) {
			return image.equals(obj);
		}

		@Override
		public Object getProperty(String name, ImageObserver observer) {
			return image.getProperty(name, observer);
		}

		@Override
		public Image getScaledInstance(int width, int height, int hints) {
			return image.getScaledInstance(width, height, hints);
		}

		@Override
		public void flush() {
			image.flush();
		}

		@Override
		public String toString() {
			return image.toString();
		}

		@Override
		public ImageCapabilities getCapabilities(GraphicsConfiguration gc) {
			return image.getCapabilities(gc);
		}

		@Override
		public void setAccelerationPriority(float priority) {
			image.setAccelerationPriority(priority);
		}

		@Override
		public float getAccelerationPriority() {
			return image.getAccelerationPriority();
		}

	}
}
