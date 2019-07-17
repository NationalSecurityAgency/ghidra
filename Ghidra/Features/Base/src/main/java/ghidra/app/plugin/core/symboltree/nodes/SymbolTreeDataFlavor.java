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
package ghidra.app.plugin.core.symboltree.nodes;

import java.awt.datatransfer.DataFlavor;

import docking.dnd.GenericDataFlavor;


public class SymbolTreeDataFlavor extends GenericDataFlavor {
	private static final String JAVA_CLASS_NAME = SymbolTreeNode.class.getName();
	public static final DataFlavor DATA_FLAVOR = new SymbolTreeDataFlavor( "Symbol Tree Node" );
	public SymbolTreeDataFlavor( String displayText ) {
		super( DataFlavor.javaJVMLocalObjectMimeType +
                "; class=" + JAVA_CLASS_NAME, displayText );
	}
}
