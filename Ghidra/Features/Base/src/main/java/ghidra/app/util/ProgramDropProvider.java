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
import java.awt.dnd.DropTargetDragEvent;

/**
 * Generic interface to handle drag and drop. 
 * 
 * 
 */
public interface ProgramDropProvider {
	/**
	 * Returns the priority of this provider.  Higher priority services will be chosen
	 * if there are multiple services that accept the same type in the same context.
	 */
	public int getPriority();
	
	/**
	 * Get the data flavors that this drop service accepts.
	 * @return an array of all DataFlavors that this drop service supports
	 */
	public DataFlavor[] getDataFlavors();
	
	/**
	 * Returns true if this service can accept a drop with the specified context.
	 * @param contextObj The object where the drop will occur
	 * @param evt The event associated with the drop that includes the dropped DataFlavors
	 */
	public boolean isDropOk(Object contextObj, DropTargetDragEvent evt);
	
	/**
	 * Adds the dropped data to this drop service.
	 * @param contextObj The object where the drop occurred
	 * @param data The actual data dropped
	 * @param flavor The selected data flavor
	 */
	public void add(Object contextObj, Object data, DataFlavor flavor);

}
