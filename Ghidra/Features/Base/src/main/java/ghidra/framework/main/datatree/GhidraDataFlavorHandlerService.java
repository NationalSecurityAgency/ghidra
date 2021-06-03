/* ###
 * IP: GHIDRA
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
package ghidra.framework.main.datatree;

import java.awt.datatransfer.DataFlavor;

public class GhidraDataFlavorHandlerService {

	public GhidraDataFlavorHandlerService() {

		//
		// Note: the order of the file drop flavors/handlers is intentional.  We wish to process
		//       objects first which we know to be transfered from within the current JVM.  After
		//       that, then process objects given to us from the OS or another JVM.
		//

		LocalTreeNodeHandler localNodeHandler = new LocalTreeNodeHandler();
		DataTreeDragNDropHandler.addActiveDataFlavorHandler(
			DataTreeDragNDropHandler.localDomainFileTreeFlavor, localNodeHandler);

		DataTreeDragNDropHandler.addActiveDataFlavorHandler(
			VersionInfoTransferable.localVersionInfoFlavor, new LocalVersionInfoHandler());
		DataTreeDragNDropHandler.addActiveDataFlavorHandler(DataFlavor.javaFileListFlavor,
			new JavaFileListHandler());

		DataFlavor linuxFileUrlFlavor =
			new DataFlavor("application/x-java-serialized-object;class=java.lang.String",
				"String file URL");
		DataTreeDragNDropHandler.addActiveDataFlavorHandler(linuxFileUrlFlavor,
			new LinuxFileUrlHandler());
	}
}
