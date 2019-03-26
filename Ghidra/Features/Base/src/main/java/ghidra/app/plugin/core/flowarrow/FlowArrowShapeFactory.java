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
package ghidra.app.plugin.core.flowarrow;

import java.awt.Shape;
import java.awt.geom.GeneralPath;

class FlowArrowShapeFactory {

	private FlowArrowShapeFactory() {
		// factory; can't create
	}

	private static final int TRIANGLE_HEIGHT = 9;
	private static final int TRIANGLE_WIDTH = 7;

	static Shape createArrowBody(FlowArrowPlugin plugin, FlowArrow arrow, int width, int height,
			int lineSpacing) {

		GeneralPath linePath = new GeneralPath();

		// Compute the start Y coordinate (place at proper offset, fix if off screen)
		Integer startTop = plugin.getStartPos(arrow.start);
		Integer startBottom = plugin.getEndPos(arrow.start);
		int startY = 0;
		if (startTop != null && startBottom != null) {
			int start = startTop;
			int end = startBottom;
			startY = (start + end) / 2;// middle of line
		}
		else if (plugin.isBelowScreen(arrow.start)) {
			startY = height;
		}

		Integer endTop = plugin.getStartPos(arrow.end);
		Integer endBottom = plugin.getEndPos(arrow.end);
		int endY = 0;
		if (endTop != null && endBottom != null) {
			int start = endTop;
			int end = endBottom;
			endY = (start + end) / 2;
			endY = Math.min(endY, height); // ensure on screen
		}
		else if (plugin.isBelowScreen(arrow.end)) {
			endY = height;
		}

		int x = width - ((arrow.depth + 1) * lineSpacing);
		if (x < 3) {
			x = 3;
		}

		// from start to middle--out line
		if (startY != 0 && startY != height) {
			/*			 
			 After this operation we will have:
			 
			 '*' is the start
			 '.' is the current position			
			 
			 | ._____*|
			 |        | 
			 |        |
			  
			 */

			linePath.moveTo(width, startY);
			linePath.lineTo(x, startY);
		}

		// the vertical bar
		/*		 
		 After this operation we will have
		
		 |  _____*|
		 | |      | 
		 | |      |
		 | .      |
		 
		 or
		 
		 |  *     |
		 |  |     | 
		 |  |     |
		 |  .     |
		  
		 */

		// straight up/down line
		boolean offScreen = (endY == 0 || endY == height);
		int arrowHeight = offScreen ? TRIANGLE_HEIGHT - 1 : 0;
		arrowHeight = arrow.isUp() ? -arrowHeight : arrowHeight;
		linePath.moveTo(x, startY); // top/corner
		linePath.lineTo(x, endY - arrowHeight);

		// straight left/right line
		if (endY != 0 && endY != height) { // completely on screen

			/*			 
			 After this operation we will have
			
			 |  _____*|
			 | |      | 
			 | |_____.|
			  
			 */

			linePath.moveTo(x, endY);
			linePath.lineTo(width - TRIANGLE_WIDTH, endY);
		}

		return linePath;
	}

	static Shape createArrowHead(FlowArrowPlugin plugin, FlowArrow arrow, int width, int height,
			int lineSpacing) {

		// Compute the start Y coordinate (place at proper offset, fix if off screen)
		Integer addrStartInt = plugin.getStartPos(arrow.end);
		Integer addrEndInt = plugin.getEndPos(arrow.end);
		int endY = 0;
		if (addrStartInt != null && addrEndInt != null) {
			int start = addrStartInt;
			int end = addrEndInt;
			endY = (start + end) / 2;
			endY = Math.min(endY, height); // ensure on screen
		}
		else if (plugin.isBelowScreen(arrow.end)) {
			endY = height;
		}

		int x = width - ((arrow.depth + 1) * lineSpacing);
		if (x < 0) {
			x = 3;
		}

		double halfHeight = TRIANGLE_HEIGHT / 2;
		GeneralPath arrowPath = new GeneralPath();
		if (endY != 0 && endY != height) { // completely on screen
			int arrowY = endY;
			arrowPath.moveTo(width, arrowY);
			arrowPath.lineTo(width - TRIANGLE_WIDTH, arrowY - halfHeight);
			arrowPath.lineTo(width - TRIANGLE_WIDTH, arrowY + halfHeight);
			arrowPath.closePath();
		}
		else if (endY == 0) {
			int offset = 0;
			arrowPath.moveTo(x, offset);
			arrowPath.lineTo(x - halfHeight, offset + TRIANGLE_WIDTH);
			arrowPath.lineTo(x + halfHeight, offset + TRIANGLE_WIDTH);
			arrowPath.closePath();
		}
		else if (endY == height) {
			arrowPath.moveTo(x, height);
			arrowPath.lineTo(x - halfHeight, height - TRIANGLE_WIDTH);
			arrowPath.lineTo(x + halfHeight, height - TRIANGLE_WIDTH);
			arrowPath.closePath();
		}

		return arrowPath;
	}
}
