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
package ghidra.framework.data;

import ghidra.app.nav.*;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import docking.ComponentProvider;

public class GhidraToolState extends ToolState implements NavigatableRemovalListener {
    private ComponentProvider activeProvider;
    private LocationMemento beforeMemento;
    private LocationMemento afterMemento;
    private Navigatable navigatable;

    public GhidraToolState(PluginTool tool, DomainObject domainObject) {
        super(tool, domainObject);
        navigatable = getNavigatable();
        if (navigatable != null) {
            LocationMemento memento = navigatable.getMemento();
            if (memento.isValid()) {
                beforeMemento = memento;
            }
            navigatable.addNavigatableListener(this);
        }
    }
    
    public void navigatableRemoved(Navigatable nav) {
        navigatable = null;
        beforeMemento = null;
        afterMemento = null;
    }
    
    private Navigatable getNavigatable() {
        activeProvider = tool.getActiveComponentProvider();
        if (activeProvider instanceof Navigatable) {
            Navigatable nav = (Navigatable) activeProvider;
            if (!nav.isConnected()) {
                return nav;
            }
        }
        GoToService service = tool.getService(GoToService.class);
        if (service != null) {
            return service.getDefaultNavigatable();
        }
        return null;
    }

    @Override
    public void getAfterState(DomainObject domainObject) {
        super.getAfterState(domainObject);
        if (navigatable != null) {
            LocationMemento memento = navigatable.getMemento();
            if (memento.isValid()) {
                afterMemento = memento;
            }
        }
    }

    @Override
    public void restoreAfterRedo(DomainObject domainObject) {
        super.restoreAfterRedo(domainObject);
        if (navigatable != null && afterMemento != null) {
        	navigatable.goTo(afterMemento.getProgram(), afterMemento.getProgramLocation());
            navigatable.setMemento( afterMemento );
            updateFocus();
        }
    }

    @Override
    public void restoreAfterUndo(DomainObject domainObject) {
        super.restoreAfterUndo(domainObject);
        if (navigatable != null && beforeMemento != null) {
        	navigatable.goTo(beforeMemento.getProgram(), beforeMemento.getProgramLocation());
            navigatable.setMemento( beforeMemento );
            updateFocus();
        }
    }
    
    private void updateFocus() {
        if ( activeProvider != null ) {
            activeProvider.requestFocus();
        }
    }
}
