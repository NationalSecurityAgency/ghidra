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
package docking.theme;

import java.awt.*;
import java.awt.color.ColorSpace;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.ColorModel;

public class GColor extends Color implements Refreshable {

	private String id;
	private Color delegate;

	public GColor(String id) {
		super(0x808080);
		this.id = id;
		delegate = Gui.getRawColor(id);
		if (delegate == null) {
			delegate = Color.gray;
		}
	}

	public String getId() {
		return id;
	}

	@Override
	public int getRed() {
		return delegate.getRed();
	}

	@Override
	public int getGreen() {
		return delegate.getGreen();
	}

	@Override
	public int getBlue() {
		return delegate.getBlue();
	}

	@Override
	public int getAlpha() {
		return delegate.getAlpha();
	}

	@Override
	public int getRGB() {
		return delegate.getRGB();
	}

	@Override
	public Color brighter() {
		return delegate.brighter();
	}

	@Override
	public Color darker() {
		return delegate.darker();
	}

	@Override
	public int hashCode() {
		return delegate.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

	@Override
	public String toString() {
		return getClass().getName() + " [id = " + id + ", " + delegate.toString() + "]";
	}

	@Override
	public float[] getRGBComponents(float[] compArray) {
		return delegate.getRGBComponents(compArray);
	}

	@Override
	public float[] getRGBColorComponents(float[] compArray) {
		return delegate.getRGBColorComponents(compArray);
	}

	@Override
	public float[] getComponents(float[] compArray) {
		return delegate.getColorComponents(compArray);
	}

	@Override
	public float[] getColorComponents(float[] compArray) {
		return delegate.getColorComponents(compArray);
	}

	@Override
	public float[] getComponents(ColorSpace cspace, float[] compArray) {
		return delegate.getComponents(cspace, compArray);
	}

	@Override
	public float[] getColorComponents(ColorSpace cspace, float[] compArray) {
		return delegate.getColorComponents(cspace, compArray);
	}

	@Override
	public ColorSpace getColorSpace() {
		return delegate.getColorSpace();
	}

	@Override
	public synchronized PaintContext createContext(ColorModel cm, Rectangle r, Rectangle2D r2d,
			AffineTransform xform, RenderingHints hints) {
		return delegate.createContext(cm, r, r2d, xform, hints);
	}

	@Override
	public int getTransparency() {
		return delegate.getTransparency();
	}

	@Override
	public void refresh() {
		Color color = Gui.getRawColor(id);
		if (color != null) {
			delegate = color;
		}
	}
}
