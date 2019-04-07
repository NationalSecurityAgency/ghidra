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

import java.awt.AWTEvent;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;

/**
 * A listener class that allows the DockingWindowsManager to be updated as the user mouses 
 * over components.
 */
class DockingWindowsContextSensitiveHelpListener {

    private static DockingWindowsContextSensitiveHelpListener instance;
    
    private DockingWindowsContextSensitiveHelpListener() {
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        AWTEventListener listener = new AWTEventListener() {            
            public void eventDispatched( AWTEvent event ) {
                DockingWindowManager.setMouseOverObject( event.getSource() );
            }
        }; 
        toolkit.addAWTEventListener( listener, AWTEvent.MOUSE_MOTION_EVENT_MASK );
    }

    static synchronized void install() {
        if ( instance == null ) {
            instance = new DockingWindowsContextSensitiveHelpListener();
        }
    }
}
