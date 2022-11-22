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
package generic.theme.laf.nimbus;

import java.awt.*;
import java.awt.geom.Rectangle2D;

import javax.swing.JComponent;
import javax.swing.plaf.nimbus.AbstractRegionPainter;

import generic.theme.GColor;

/**
 * Nimbus selected tree row painter
 */
public class SelectedTreePainter extends AbstractRegionPainter {

	private PaintContext paintContext = new MyPaintContext();
	private Rectangle2D shape = new Rectangle2D.Float();
	private Color selectionColor;

	@Override
	protected PaintContext getPaintContext() {
		return paintContext;
	}

	@Override
	protected void doPaint(Graphics2D g, JComponent c, int width, int height,
			Object[] extendedCacheKeys) {
		lazyLoadColor();
		updateShape();
		g.setPaint(selectionColor);
		g.fill(shape);
	}

	private void lazyLoadColor() {
		//
		// This class gets created before the theme system is full bootstrapped.  By lazy loading,
		// we ensure the property is available after the theme system is loaded.
		//
		if (selectionColor == null) {
			selectionColor = new GColor("color.bg.tree.selected");
		}
	}

	private void updateShape() {
		float x = 0;
		float y = 0;
		float w = decodeX(3.0f);
		float h = decodeY(3.0f);
		shape.setRect(x, y, w, h);
	}

	private class MyPaintContext extends PaintContext {
		public MyPaintContext() {
			super(new Insets(5, 5, 5, 5), new Dimension(100, 30),
				false, CacheMode.NO_CACHING, 1.0, 1.0);
		}
	}
}
