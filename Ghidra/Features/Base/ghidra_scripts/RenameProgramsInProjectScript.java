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
// Shows how to perform an operation on all of the files within the current project
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.InvalidNameException;

import java.io.IOException;

public class RenameProgramsInProjectScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        if ( currentProgram != null ) {
            popup( "This script should be run from a tool with no open programs" );
            return;
        }
        
        PluginTool tool = state.getTool();
        Project project = tool.getProject();
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        recurseProjectFolder( rootFolder );
    }
    
    private void recurseProjectFolder( DomainFolder domainFolder ) {
        DomainFile[] files = domainFolder.getFiles();
        for ( DomainFile domainFile : files ) {
            processDomainFile( domainFile );
        }
        DomainFolder[] folders = domainFolder.getFolders();
        for ( DomainFolder folder : folders ) {
            recurseProjectFolder( folder );
        }
    }
    
    private void processDomainFile( DomainFile domainFile ) {
        String oldName = domainFile.getName();
        try {
            domainFile.setName( oldName + "_renamed" );
        }
        catch ( InvalidNameException e ) {
            e.printStackTrace();
        }
        catch ( IOException e ) {
            e.printStackTrace();
        }
    }
}
