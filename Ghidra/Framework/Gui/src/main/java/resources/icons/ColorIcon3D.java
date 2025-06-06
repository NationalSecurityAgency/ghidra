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
package resources.icons;

import java.awt.*;

import javax.swing.Icon;

public class ColorIcon3D implements Icon {
   	private final Color color;
   	private final int width;
   	private final int height;
   	
	public ColorIcon3D(Color color) {
		this.color = color;
		this.width = 16;
		this.height = 16;
	}
	
	public ColorIcon3D( Color color, int width, int height  ) {
	    this.color = color;
	    this.width = width;
	    this.height = height;
	}
	
	@Override
	public int getIconHeight() {
		return height;
	}

	@Override
	public int getIconWidth() {
		return width;
	}
	public Color getColor() {
		return color;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
	    Color startColor = g.getColor();	    
		g.setColor(getColor());
		g.fill3DRect( x, y, width, height, true );		
		g.setColor( startColor );
	}
}
