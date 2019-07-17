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
package ghidra.app.plugin.core.datamgr.util;

import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.services.DataService;
import ghidra.app.util.ProgramDropProvider;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeTransferable;

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDragEvent;

/**
 *  Handles datatype drops in the codebrowser.  Installed by the dataTypeManagerPlugin
 *
 */
public class DataDropOnBrowserHandler implements ProgramDropProvider { 
	
	private static final DataFlavor[] ACCEPTABLE_FLAVORS = new DataFlavor[] {
	    DataTypeTransferable.localDataTypeFlavor,
	    DataTypeTransferable.localBuiltinDataTypeFlavor
	};
	private DataService curService;
	private final DataTypeManagerPlugin plugin;

	public DataDropOnBrowserHandler(DataTypeManagerPlugin plugin) {
		this.plugin = plugin;
	}
	
	public int getPriority() {
		return 20;
	}
	
	public DataFlavor[] getDataFlavors() {
		return ACCEPTABLE_FLAVORS;
	}

	/**
	 * @see ghidra.app.util.ProgramDropProvider#isDropOk(java.lang.Object, java.awt.dnd.DropTargetDragEvent)
	 */
	public boolean isDropOk(Object contextObj, DropTargetDragEvent evt) {
		curService = null;

		if (!evt.isDataFlavorSupported(DataTypeTransferable.localDataTypeFlavor) &&
		    !evt.isDataFlavorSupported(DataTypeTransferable.localBuiltinDataTypeFlavor) )
			return false;

		if (contextObj != null  &&  contextObj instanceof ListingActionContext) {
			ListingActionContext pl = (ListingActionContext)contextObj;
			DataService[] services = plugin.getTool().getServices(DataService.class); 
			for (int i=0; i<services.length; i++) {
				if (services[i].isCreateDataAllowed(pl)) {
					curService = services[i];
					return true;
				}
			}
		}
		
		return false;
	}

	public void add(Object contextObj, Object data, DataFlavor flavor) {
		if (curService != null) {
			DataType dt = (DataType)data;
			curService.createData(dt, (ListingActionContext)contextObj, true);
		}
	}
	
}
