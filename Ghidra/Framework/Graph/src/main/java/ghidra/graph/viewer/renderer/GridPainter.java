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
package ghidra.graph.viewer.renderer;

import java.awt.Color;
import java.awt.Rectangle;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.graph.viewer.layout.GridCoordinates;

/**
 * Class for painting the underlying grid used to layout a graph. Used as a visual aid when 
 * debugging grid based graph layouts.
 */
public class GridPainter {

	private GridCoordinates grid;

	public GridPainter(GridCoordinates gridCoordinates) {
		this.grid = gridCoordinates;
	}

	public void paintLayoutGridCells(RenderContext<?, ?> renderContext, Layout<?, ?> layout) {

		if (grid == null) {
			return;
		}
		int rowCount = grid.rowCount();
		int colCount = grid.columnCount();

		GraphicsDecorator g = renderContext.getGraphicsContext();
		Color originalColor = g.getColor();
		Color gridColor = Palette.ORANGE;
		Color textColor = Palette.BLACK;

		Rectangle bounds = grid.getBounds();
		int width = bounds.width;
		int height = bounds.height;

		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		int previous = -1;
		for (int row = 0; row < rowCount; row++) {
			int y = grid.y(row);
			if (y == previous) {
				continue; 		// don't paint empty rows
			}
			previous = y;
			Point2D start = new Point2D.Double(0, y);
			Point2D end = new Point2D.Double(width, y);
			start = transformer.transform(Layer.LAYOUT, start);
			end = transformer.transform(Layer.LAYOUT, end);

			g.setColor(textColor);
			g.drawString(Integer.toString(row), (float) start.getX() - 20,
				(float) (start.getY() + 5));

			g.setColor(gridColor);
			g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());
		}

		previous = -1;
		for (int col = 0; col < colCount; col++) {
			int x = grid.x(col);
			if (x == previous) {
				continue;
			}
			previous = x;
			Point2D start = new Point2D.Double(x, 0);
			Point2D end = new Point2D.Double(x, height);
			start = transformer.transform(Layer.LAYOUT, start);
			end = transformer.transform(Layer.LAYOUT, end);

			g.setColor(textColor);
			g.drawString(Integer.toString(col), (float) start.getX() - 5,
				(float) (start.getY() - 10));

			g.setColor(gridColor);
			g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());
		}

		g.setColor(originalColor);
	}

}
