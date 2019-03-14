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
package ghidra.framework.project.tool;

import ghidra.app.util.FileOpenDropHandler;
import ghidra.framework.plugintool.PluginTool;

import java.awt.Component;

import docking.DropTargetFactory;
import docking.DropTargetHandler;

/**
 * A basic DropTargetFactory that provides functionality for dragging files onto Ghidra to be 
 * opened.
 */
class OpenFileDropHandlerFactory implements DropTargetFactory {

    private final PluginTool tool;

    OpenFileDropHandlerFactory( PluginTool tool ) {
        this.tool = tool;
        
    }
    
    public DropTargetHandler createDropTargetHandler( Component component ) {
        return new FileOpenDropHandler( tool, component );
    }

}
