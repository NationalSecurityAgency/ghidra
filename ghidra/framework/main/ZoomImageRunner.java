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

import java.awt.Rectangle;

import javax.swing.Icon;

import org.jdesktop.animation.timing.*;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

/**
 * A class to change the bounds of a given {@link ZoomedImagePainter} to make the Icon appear to 
 * grow and fade away over time.  This class handles setup for the painter and then makes changes
 *  on the painter by using callbacks from the {@link Animator}.
 */
class ZoomImageRunner {
    private static final float DEFAULT_MAGNIFY_FACTOR = 25.0f;
    
    private GGlassPane dockingGlassPane;
    private Animator animator;
    private TimingTarget finishedCallbackTarget;
    
    public ZoomImageRunner( GGlassPane glassPane, final ZoomedImagePainter painter, Icon icon ) {
        this.dockingGlassPane = glassPane;
        
        glassPane.addPainter( painter );

        animator = createSpringAnimator( glassPane.getBounds(), icon.getIconWidth(), painter );            
        animator.addTarget( new TimingTargetAdapter() {
            @Override
            public void end() {
                // cleanup
                dockingGlassPane.removePainter( painter );
                dockingGlassPane.repaint();
                
                if ( finishedCallbackTarget != null ) {
                    finishedCallbackTarget.end();
                }
            }
            
            @Override
            public void timingEvent( float fraction ) {
                // things have changed...
                dockingGlassPane.repaint();
            }
        } );
    }

    /** Allows clients to add a callback mechanism for timing events */
    public void addTimingTargetListener( TimingTarget newFinishedTarget ) {
        this.finishedCallbackTarget = newFinishedTarget;
    }

    public void run() {
        animator.start();
    }
    
    private Animator createSpringAnimator( Rectangle iconContainerBounds, int imageWidth,
            ZoomedImagePainter iconPainter ) {
        float magnifyFactor = recalculateMagnifyFactor( iconContainerBounds, imageWidth );
        iconPainter.setMagnifyFactor( magnifyFactor );

        // changes the 'zoom' field on the painter via the setters/getters
        Animator newAnimator = PropertySetter.createAnimator( 850, iconPainter, "zoom", 0.0f, 1.0f );
        newAnimator.setAcceleration( 0.2f );
        newAnimator.setDeceleration( 0.2f );
        return newAnimator;
    }

    private float recalculateMagnifyFactor( Rectangle containerBounds, int imageWidth ) {
        double width = containerBounds.getWidth();
        return Math.min( DEFAULT_MAGNIFY_FACTOR, ((float) (width / imageWidth)) * 1.25f );
    }
}
