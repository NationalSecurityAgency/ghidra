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
package ghidra.app.plugin.core.progmgr;

import java.io.IOException;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Action class for the "redo" action
 */
public class RedoAction extends AbstractUndoRedoAction {
	public static final String SUBGROUP = "2Redo";

	public RedoAction(ProgramManagerPlugin plugin, PluginTool tool) {
		super(tool, plugin, "Redo", "images/redo.png", "ctrl shift Z", SUBGROUP);
	}

	@Override
	protected void actionPerformed(Program program) throws IOException {
		program.redo();
	}

	@Override
	protected boolean canPerformAction(Program program) {
		return program != null && program.canRedo();
	}

	@Override
	protected String getUndoRedoDescription(Program program) {
		return program.getRedoName();
	}
}
