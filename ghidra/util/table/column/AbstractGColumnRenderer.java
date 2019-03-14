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
package ghidra.util.table.column;

import docking.widgets.table.GTableCellRenderer;

/**
 * A convenience base class that combines the {@link GTableCellRenderer} with the 
 * {@link GColumnRenderer} interface.
 * 
 * <P>Table columns that wish to provider a renderer will have to implement the 
 * {@link GColumnRenderer} interface.  Rather then implement that interface and extend
 * the {@link GTableCellRenderer}, clients can simply extends this class.
 *  
 * @param <T> the column type
 */
public abstract class AbstractGColumnRenderer<T> extends GTableCellRenderer
		implements GColumnRenderer<T> {

	// nothing yet; convenience interface
}
