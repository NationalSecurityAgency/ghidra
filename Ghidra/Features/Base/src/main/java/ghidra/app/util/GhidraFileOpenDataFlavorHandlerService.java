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
package ghidra.app.util;

import java.awt.datatransfer.DataFlavor;

import ghidra.framework.main.datatree.*;

public class GhidraFileOpenDataFlavorHandlerService {

	public GhidraFileOpenDataFlavorHandlerService() {

		try {
			DataFlavor linuxFileUrlFlavor =
				new DataFlavor("application/x-java-serialized-object;class=java.lang.String");
			FileOpenDropHandler.addDataFlavorHandler(linuxFileUrlFlavor, new LinuxFileUrlHandler());
		}
		catch (ClassNotFoundException cnfe) {
			// should never happen as it is using java.lang.String
		}

		LocalTreeNodeHandler localHandler = new LocalTreeNodeHandler();
		FileOpenDropHandler.addDataFlavorHandler(DataTreeDragNDropHandler.localDomainFileFlavor,
			localHandler);
		FileOpenDropHandler.addDataFlavorHandler(DataTreeDragNDropHandler.localDomainFileTreeFlavor,
			localHandler);

		FileOpenDropHandler.addDataFlavorHandler(VersionInfoTransferable.localVersionInfoFlavor,
			new LocalVersionInfoHandler());
		FileOpenDropHandler.addDataFlavorHandler(DataFlavor.javaFileListFlavor,
			new JavaFileListHandler());
	}
}
