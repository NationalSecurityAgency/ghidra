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
package resources.icons;

import java.awt.*;

import javax.swing.Icon;

/** 
 * Paints an oval of the given size, based upon the Component passed to 
 * {@link #paintIcon(Component, Graphics, int, int)}.  If the component is null, then no 
 * painting will take place.
 */
public class OvalBackgroundColorIcon implements Icon {

    private final int width;
    private final int height;

    public OvalBackgroundColorIcon( int width, int height ) {
        this.width = width;
        this.height = height;        
    }
    
    public int getIconHeight() {
        return height;
    }

    public int getIconWidth() {
        return width;
    }

    public void paintIcon( Component c, Graphics g, int x, int y ) {
        if ( c == null ) {
            return;
        }
        
        Color color = c.getBackground();
        g.setColor( color );
        g.fillOval( x, y, width, height );
    }

}
