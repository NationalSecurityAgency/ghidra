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
/**
 * 
 */
package ghidra.app.util;

import ghidra.framework.main.*;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;

import java.awt.datatransfer.*;
import java.awt.dnd.*;

final class LocalVersionInfoFlavorHandler implements
        FileOpenDataFlavorHandler {
    public void handle(PluginTool tool, Object obj, DropTargetDropEvent e, DataFlavor f) {
        VersionInfo info = (VersionInfo) obj;
        
        DomainFile file = tool.getProject().getProjectData().getFile(info.getDomainFilePath());
        GetVersionedObjectTask task = new GetVersionedObjectTask(this, file, 
            info.getVersionNumber());
        tool.execute(task, 250);
        DomainObject versionedObj = task.getVersionedObject();

        if (versionedObj != null) {
            DomainFile vfile = versionedObj.getDomainFile();
            tool.acceptDomainFiles(new DomainFile[] {vfile});
            versionedObj.release(this);
        }
    }
}
