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
package ghidra.bitpatterns.gui;

import java.awt.Component;
import java.util.List;

import ghidra.bitpatterns.info.*;

/**
 * 
 * This class is used to create a simple byte sequence analyzer, which does not have
 * the ability to call the pattern miner.
 *
 */
public class SimpleByteSequenceAnalyzerProvider extends ByteSequenceAnalyzerProvider {
	public static final String TITLE_INITIAL = "Byte Sequences for ";

	/**
	 * 
	 * @param plugin plugin
	 * @param pathFilterString description of path constraining these sequences
	 * @param contextRegisterFilter {@link ContextRegisterFilter} constraining these sequences
	 * @param rowObjects row objects to analyzer
	 * @param parent parent component
	 * @param type pattern type
	 */
	public SimpleByteSequenceAnalyzerProvider(FunctionBitPatternsExplorerPlugin plugin,
			String pathFilterString, ContextRegisterFilter contextRegisterFilter,
			List<ByteSequenceRowObject> rowObjects, Component parent, PatternType type) {
		super(TITLE_INITIAL + pathFilterString, plugin, rowObjects, parent, type,
			contextRegisterFilter, pathFilterString);
	}

	@Override
	ByteSequenceTableModel createByteSequenceTable(FunctionBitPatternsExplorerPlugin fPlugin,
			List<ByteSequenceRowObject> rowObjects) {
		return new DisassembledByteSequenceTableModel(plugin, rowObjects);
	}

}
