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
package ghidra.feature.vt.gui.task;

import ghidra.feature.vt.gui.wizard.VTWizardUtils;
import ghidra.framework.model.DomainFile;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

public class SaveTask extends Task {

    private final DomainFile domainFile;
    private boolean didSave;

    public SaveTask( DomainFile domainFile ) {
        super( "Saving File: " + domainFile.getName(), true, true, true );
        this.domainFile = domainFile;
    }
    
    @Override
    public void run( TaskMonitor monitor ) {
        monitor.setMessage("Saving " + domainFile.getName() + "...");
        try {
            domainFile.save( monitor );
            didSave = true;
        }
        catch ( CancelledException e ) {
            // OK
            didSave = false;
        }
        catch ( IOException e ) {
            Msg.error( VTWizardUtils.class, "Unexpected error saving file", e );
            didSave = false;
        }
    }
    
    public boolean didSave() {
        return didSave;
    }
}
