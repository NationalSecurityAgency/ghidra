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
package ghidra.app.util;

import ghidra.framework.PluggableServiceRegistry;
import ghidra.framework.main.datatree.DataTreeDragNDropHandler;
import ghidra.framework.main.datatree.VersionInfoTransferable;

public class FileOpenDataFlavorHandlerService {
    static {
        PluggableServiceRegistry.registerPluggableService(FileOpenDataFlavorHandlerService.class, new FileOpenDataFlavorHandlerService());
    }

    public static void registerDataFlavorHandlers() {
        FileOpenDataFlavorHandlerService factory = PluggableServiceRegistry.getPluggableService(FileOpenDataFlavorHandlerService.class);
        factory.doRegisterDataFlavorHandlers();
    }

    protected void doRegisterDataFlavorHandlers() {
        FileOpenDropHandler.addDataFlavorHandler(DataTreeDragNDropHandler.localDomainFileFlavor, new LocalTreeNodeFlavorHandler());
        FileOpenDropHandler.addDataFlavorHandler(VersionInfoTransferable.localVersionInfoFlavor, new LocalTreeNodeFlavorHandler());
    }
}
