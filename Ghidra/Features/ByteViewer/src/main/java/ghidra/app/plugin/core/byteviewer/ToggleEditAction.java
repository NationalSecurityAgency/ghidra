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
package ghidra.app.plugin.core.byteviewer;

import ghidra.framework.plugintool.Plugin;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

    class ToggleEditAction extends ToggleDockingAction {
    	private final ByteViewerComponentProvider provider;
    	public ToggleEditAction(ByteViewerComponentProvider provider, Plugin plugin) {
    		super("Enable/Disable Byteviewer Editing", plugin.getName());
			this.provider = provider;
    		setToolBarData( new ToolBarData( 
    			ResourceManager.loadImage( "images/editbytes.gif" ), "Byteviewer" ) );
    		setKeyBindingData( new KeyBindingData( 
    			KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK ) );

    		setDescription("Enable/Disable editing of bytes in Byte Viewer panels.");
    		setSelected(false);
    		setEnabled(true);
		}
        @Override
        public void actionPerformed(ActionContext context) {
			boolean isSelected = isSelected(); 
            provider.setEditMode(isSelected);
        }
    }
