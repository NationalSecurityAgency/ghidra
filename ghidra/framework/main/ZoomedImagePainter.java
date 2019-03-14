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
package ghidra.framework.main;

import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;

import java.awt.*;
import java.awt.image.BufferedImage;

import javax.swing.Icon;

/**
 * A class that paints a given image with varying zoom levels.  The zoom is set by clients 
 * according to changes made by an {@link org.jdesktop.animation.timing.Animator}.  In essence, 
 * this class paints the given image centered over the given target bounds at some 
 * level of zoom.  If the zoom or bounds of the parent container are never changed, 
 * then the image painted by this class will not change.
 * <p>
 * NOTE: This class and it's getters/setters need to be public for reflective callbacks
 */
public class ZoomedImagePainter implements GGlassPanePainter {

    private Rectangle targetBounds; // we paint centered over these bounds, which may change
    private Image image;

    private float zoom = 0.0f; // how far zoomed to draw
    private float magnifyFactor = 10.0f; // how to draw the zoom; may change

    public ZoomedImagePainter( Rectangle targetBounds, Image image ) {
        this.targetBounds = targetBounds;
        this.image = image;
    }

    public void paint( GGlassPane glassPane, Graphics g ) {
        if ( image == null || targetBounds == null ) {
            return;
        }

        // the width is based upon the magnify factor and the 
        // zoom (set by the animator's progress)
        int imageWidth = image.getWidth( null );
        int width = imageWidth + (int) (imageWidth * magnifyFactor * getZoom());

        // the height is also based upon the magnify factor and the 
        // zoom (set by the animator's progress)
        int imageHeight = image.getHeight( null );
        int height = imageHeight + (int) (imageHeight * magnifyFactor * getZoom());

        // calculate the coordinates, centering the image drawing over the container's bounds
        int middleBoundsX = targetBounds.width >> 1;
        int middleBoundsY = targetBounds.height >> 1;
        int middleWidthX = width >> 1;
        int middleHeightY = height >> 1;
        int x = middleBoundsX - middleWidthX + targetBounds.x;
        int y = middleBoundsY - middleHeightY + targetBounds.y;

        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint( RenderingHints.KEY_INTERPOLATION,
            RenderingHints.VALUE_INTERPOLATION_BILINEAR );

        float alpha = 1.0f - zoom;

//      This lets the image stay until clear() is called                
//      alpha = Math.max( 0.1f, alpha );
        g2.setComposite( AlphaComposite.getInstance( AlphaComposite.SrcOver.getRule(), alpha ) );

        g2.drawImage( image, x, y, width, height, null );
    }

    public float getZoom() {
        return zoom;
    }

    // callback for timing framework
    public void setZoom( float zoom ) {        
        this.zoom = zoom;
    }

    public Rectangle getTargetBounds() {
        return targetBounds;
    }

    // callback for timing framework
    public void setTargetBounds( Rectangle containerBounds ) {
        this.targetBounds = containerBounds;
    }

    public void setMagnifyFactor( float factor ) {
        this.magnifyFactor = factor;
    }

    public static Image createIconImage( Icon icon ) {
        BufferedImage buffImage = new BufferedImage( icon.getIconWidth(), 
            icon.getIconHeight(), BufferedImage.TYPE_INT_ARGB );
        Graphics graphics = buffImage.getGraphics();
        icon.paintIcon( null, graphics, 0, 0 );
        graphics.dispose();
        return buffImage;
    }
}
