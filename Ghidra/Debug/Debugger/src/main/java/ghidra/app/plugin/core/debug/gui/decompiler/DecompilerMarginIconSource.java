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
package ghidra.app.plugin.core.debug.gui.decompiler;

import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.Icon;

import ghidra.app.decompiler.ClangLine;
import ghidra.program.model.listing.Program;

/**
 * A source of icons for the Debugger's icon margin in the Decompiler
 *
 * @see DebuggerDecompilerMarginService
 */
public interface DecompilerMarginIconSource {
	/**
	 * Get the icon to display beside the given line
	 *
	 * @param program the program the line was decompiled from
	 * @param line the line
	 * @return the icon, or null for no icon
	 */
	Icon getIcon(Program program, ClangLine line);

	/**
	 * Get the priority of this source's icons
	 *
	 * <p>
	 * When several sources have an icon for the same line, they are painted in order of increasing
	 * priority, so the highest priority icon is on top. These follow the same convention as the
	 * priorities given to the {@link ghidra.app.services.MarkerService}.
	 *
	 * @return the priority
	 */
	int getPriority();

	/**
	 * The user pressed a mouse button in the margin
	 *
	 * @param program the program the lines were decompiled from
	 * @param index the index of the line under the mouse
	 * @param lines the complete list of decompiled lines
	 * @param e the mouse event
	 */
	default void marginPressed(Program program, int index, List<ClangLine> lines,
			MouseEvent e) {
		// Optional
	}
}
