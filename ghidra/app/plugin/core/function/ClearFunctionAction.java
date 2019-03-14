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
package ghidra.app.plugin.core.function;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.data.DataType;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;


/**
 * <CODE>ClearFunctionAction</CODE> allows the user to perform a clear of function data 
 * at the entry point of the function.
 * <p>
 * The actual work performed by this action depends upon the location of the cursor in the 
 * code browser.  Further, multiple instances of this action are created to handel different 
 * pieces of the function, like the signature, parameters, etc.
 */
class ClearFunctionAction extends ListingContextAction {
    FunctionPlugin funcPlugin;
	private Class<?> locationEnabledClass;

    /**
     * Creates a new action with the given name and associated to the given
     * plugin.
     * @param name the name for this action.
     * @param plugin the plugin this action is associated with.
     */
    ClearFunctionAction(String name, FunctionPlugin plugin, Class<?> locationEnabledClass) {
        super(name, plugin.getName());
        this.funcPlugin = plugin;
        this.locationEnabledClass = locationEnabledClass;

        setKeyBindingData( new KeyBindingData( 
        	KeyEvent.VK_C, 0 ) );

    }

    @Override
    public void actionPerformed(ListingActionContext context) {
		funcPlugin.createData(DataType.DEFAULT, context, false);
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
    	if (context.hasSelection() || context.getAddress() == null) {
    		return false;
    	}
        return locationEnabledClass.isAssignableFrom(context.getLocation().getClass());
    }
}


