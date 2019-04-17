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

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

/** 
 * Changes the 'containerBounds' field on the {@link ZoomedImagePainter} via the 
 * setters/getters in order to move where the painter paints.
 */
class MoveImageRunner {

    private Animator animator;
    private final GGlassPane dockingGlassPane;

    public MoveImageRunner( GGlassPane ghidraGlassPane, Rectangle startBounds,
            Rectangle endBounds, ZoomedImagePainter painter ) {
        this( ghidraGlassPane, startBounds, endBounds, painter, false );
    }
    
    /**
     * Changes the bounds of the given painter over a period of time
     * 
     * @param ghidraGlassPane The glass pane we are using to paint
     * @param startBounds The start position and size
     * @param endBounds The end position and size
     * @param painter The painter upon which we will update bounds
     * @param repaint true signals to repaint as the changes are made.  This can lead to 
     *        choppiness when using other animators in conjunction with the one used by this
     *        class.
     */
    public MoveImageRunner( GGlassPane ghidraGlassPane, Rectangle startBounds, 
            Rectangle endBounds, ZoomedImagePainter painter, boolean repaint ) {
        this.dockingGlassPane = ghidraGlassPane;
        
        // changes the 'containerBounds' field on the painter via the setters/getters
        // note: a smaller duration here allows more location changing to be painted
        animator = PropertySetter.createAnimator( 200, painter, 
            "targetBounds", startBounds, endBounds );
        animator.setAcceleration( 0.2f );
        animator.setDeceleration( 0.4f );

        if ( repaint ) {
            animator.addTarget( new TimingTargetAdapter() {
                @Override
                public void end() {
                    dockingGlassPane.repaint();
                }

                @Override
                public void timingEvent( float fraction ) {
                    dockingGlassPane.repaint();
                }
            });
        }
    }

    public void run() {
        animator.start();
    }
}
