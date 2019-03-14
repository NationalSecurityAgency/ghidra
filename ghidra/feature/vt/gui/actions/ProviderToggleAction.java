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
package ghidra.feature.vt.gui.actions;

import ghidra.framework.plugintool.ComponentProviderAdapter;

import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;

public class ProviderToggleAction extends ToggleDockingAction {

    private static final String TOOL_BAR_GROUP = "ZGroup";
    private final ComponentProviderAdapter componentProvider;

    public ProviderToggleAction( ComponentProviderAdapter provider ) {
        super( "Show " + provider.getTitle(), provider.getOwner(), false );
        this.componentProvider = provider;
        
        setSelected( true );
        setToolBarData( new ToolBarData( provider.getIcon(), TOOL_BAR_GROUP ) );
        
        installVisibilityTracker( provider );
    }
    
    private void installVisibilityTracker( final ComponentProviderAdapter provider ) {
        JComponent component = provider.getComponent();
        component.addHierarchyListener( new HierarchyListener() {
            
            public void hierarchyChanged( HierarchyEvent e ) {
                long changeFlags = e.getChangeFlags();
                if ( HierarchyEvent.SHOWING_CHANGED ==
                    (changeFlags & HierarchyEvent.SHOWING_CHANGED) ) {
                    setSelected( provider.isVisible() );
                }
            }
        } );
    }
    
    @Override
    public void actionPerformed( ActionContext context ) {
        componentProvider.setVisible( isSelected() );
    }
    
}
