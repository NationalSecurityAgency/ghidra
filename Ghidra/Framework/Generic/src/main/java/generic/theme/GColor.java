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
package generic.theme;

import java.awt.*;
import java.awt.color.ColorSpace;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.ColorModel;
import java.util.Objects;

import ghidra.util.WebColors;
import ghidra.util.datastruct.WeakStore;

/**
 * A {@link Color} whose value is dynamically determined by looking up its id into a global
 * color table that is determined by the active {@link GTheme}. 
 * <P>The idea is for developers to
 * not use specific colors in their code, but to instead use a GColor with an id that hints at 
 * its use. For example, instead of hard coding a component's background color to white by coding
 * "component.setBackground(Color.white)", you would do something like 
 * "component.setBackground(new GColor("color.mywidget.bg"). Then in a 
 * "[module name].theme.properties" file (located in the module's data directory), you would 
 * set the default value by adding this line "color.mywidget.bg = white".
 */
public class GColor extends Color {
	// keeps a weak reference to all uses of GColor, so their cached color value can be refreshed 
	private static WeakStore<GColor> inUseColors = new WeakStore<>();

	private String id;
	private Color delegate;
	private Short alpha;

	/**
	 * Construct a GColor with an id that will be used to look up the current color associated with 
	 * that id, which can be changed at runtime.
	 * @param id the id used to lookup the current value for this color
	 */
	public GColor(String id) {
		super(0x808080);
		this.id = id;
		delegate = Gui.getColor(id);
		inUseColors.add(this);

	}

	private GColor(String id, int alpha) {
		this(id);
		this.alpha = (short) alpha;
		delegate = new Color(delegate.getRed(), delegate.getGreen(), delegate.getBlue(), alpha);
	}

	/**
	 * Creates a transparent version of this GColor. If the underlying value of this GColor changes,
	 * the transparent version will also change.
	 * @param newAlpha the transparency level for the new color
	 * @return a transparent version of this GColor
	 */
	public GColor withAlpha(int newAlpha) {
		return new GColor(id, newAlpha);
	}

	/**
	 * Returns the id for this GColor.
	 * @return the id for this GColor.
	 */
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

	/**
	 * Returns true if this GColor could not find a value for its color id in the current theme
	 * and is using the default color as its delegate
	 * @return true if this GColor could not find a value for its color id in the current theme
	 */
	public boolean isUnresolved() {
		return delegate == ColorValue.LAST_RESORT_DEFAULT;
	}

	@Override
	public String toString() {
		return toHexString();
	}

	/**
	 * Returns this color as a hex string that starts with '#'
	 * @return the hex string
	 */
	public String toHexString() {
		return WebColors.toString(this, false);
	}

	/**
	 * Generates a more verbose toString()
	 * @return a more verbose toString()
	 */
	public String toDebugString() {
		Color c = delegate;
		String rgb =
			"(" + c.getRed() + "," + c.getGreen() + "," + c.getBlue() + "," + c.getAlpha() + ")";
		String hexrgb = "(" + WebColors.toString(c, true) + ")";
		return getClass().getSimpleName() + " [id = " + id + ", color = " +
			c.getClass().getSimpleName() + rgb + hexrgb + "]";
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, alpha);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GColor other = (GColor) obj;
		return Objects.equals(id, other.id) && Objects.equals(alpha, other.alpha);
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

	/**
	 * Reloads the delegate.
	 * @param currentValues the map of current theme values
	 */
	public void refresh(GThemeValueMap currentValues) {
		ColorValue value = currentValues.getColor(id);
		Color color = value == null ? null : value.get(currentValues);
		if (color != null) {
			if (alpha != null) {
				delegate = new Color(color.getRed(), color.getGreen(), color.getBlue(), alpha);
			}
			else {
				delegate = color;
			}
		}
	}

	/**
	 * Static method for notifying all the existing GColors that colors have changed and they
	 * should reload their cached indirect color. 
	 * @param currentValues the map of current theme values
	 */
	public static void refreshAll(GThemeValueMap currentValues) {
		for (GColor gcolor : inUseColors.getValues()) {
			gcolor.refresh(currentValues);
		}
	}

}
