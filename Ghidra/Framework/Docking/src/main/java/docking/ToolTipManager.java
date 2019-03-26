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
package docking;

import javax.swing.JComponent;

/**
 * A tooltip manager that simply delegates to the Swing tooltip manager.  This class replaces
 * the previous tooltip manager that overrode much of the Swing tooltip manager's functionality.
 */
public class ToolTipManager {

    private javax.swing.ToolTipManager delegate = javax.swing.ToolTipManager.sharedInstance();
    
    private static ToolTipManager sharedInstance = new ToolTipManager();
    
    /**
     * Registers a component for tooltip management.
     * <p>
     * This will register key bindings to show and hide the tooltip text
     * only if <code>component</code> has focus bindings. This is done
     * so that components that are not normally focus traversable, such
     * as <code>JLabel</code>, are not made focus traversable as a result
     * of invoking this method.
     *
     * @param component  a <code>JComponent</code> object to add
     * @see JComponent#isFocusTraversable
     */
    public void registerComponent(JComponent component) {
        delegate.registerComponent( component );
    }
    
    /**
     * Removes a component from tooltip control.
     *
     * @param component  a <code>JComponent</code> object to remove
     */
    public void unregisterComponent(JComponent component) {
        delegate.unregisterComponent( component );
    }

    public int getDismissDelay() {
        return delegate.getDismissDelay();
    }

    public int getReshowDelay() {
        return delegate.getReshowDelay();
    }

    public boolean isEnabled() {
        return delegate.isEnabled();
    }

    public int getInitialDelay() {
        return delegate.getInitialDelay();
    }
    
    public boolean isLightWeightPopupEnabled() {
        return delegate.isLightWeightPopupEnabled();
    }

    public void setLightWeightPopupEnabled( boolean aFlag ) {
        delegate.setLightWeightPopupEnabled( aFlag );
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    public static void setToolTipText( JComponent c, String text ) {
        String oldText = (String) c.getClientProperty(JComponent.TOOL_TIP_TEXT_KEY);
        c.putClientProperty(JComponent.TOOL_TIP_TEXT_KEY, text);
        if (text != null) {
            if (oldText == null) {
                sharedInstance.registerComponent(c);
            }
        } else {
            sharedInstance.unregisterComponent(c);
        }
    }
    
    public static ToolTipManager sharedInstance() {
        javax.swing.ToolTipManager.sharedInstance();
        return sharedInstance;
    }
    
    /**
     * Enables or disables the tooltip.
     *
     * @param flag  true to enable the tip, false otherwise
     */
    public void setEnabled( boolean flag ) {
        delegate.setEnabled( flag );
    }

    /**
     * Specifies the initial delay value.
     *
     * @param milliseconds  the number of milliseconds to delay
     *        (after the cursor has paused) before displaying the
     *        tooltip
     * @see #getInitialDelay
     */
    public void setInitialDelay( int milliseconds ) {
        delegate.setInitialDelay( milliseconds );
    }

    /**
     * Specifies the dismissal delay value.
     *
     * @param milliseconds  the number of milliseconds to delay
     *        before taking away the tooltip
     * @see #getDismissDelay
     */
    public void setDismissDelay( int milliseconds ) {
        delegate.setDismissDelay( milliseconds );
    }

    /**
     * Used to specify the amount of time before the user has to wait
     * <code>initialDelay</code> milliseconds before a tooltip will be
     * shown. That is, if the tooltip is hidden, and the user moves into
     * a region of the same Component that has a valid tooltip within
     * <code>milliseconds</code> milliseconds the tooltip will immediately
     * be shown. Otherwise, if the user moves into a region with a valid
     * tooltip after <code>milliseconds</code> milliseconds, the user
     * will have to wait an additional <code>initialDelay</code>
     * milliseconds before the tooltip is shown again.
     *
     * @param milliseconds time in milliseconds
     * @see #getReshowDelay
     */
    public void setReshowDelay( int milliseconds ) {
        delegate.setReshowDelay( milliseconds );
    }

    /** Hides any open tooltip window */
    public void hideTipWindow() {        
        // This is a hack, since Java's manager doesn't have this method
        delegate.setEnabled( false );
        delegate.setEnabled( true );
        
// TODO: Ultimately, the ESCAPE key binding in the Java TTM should hide any visible tooltips.  We
//       need to look into why this isn't working.
    }
} 
