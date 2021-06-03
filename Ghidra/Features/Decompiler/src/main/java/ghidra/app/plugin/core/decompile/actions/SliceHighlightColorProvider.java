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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.Color;
import java.util.Set;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A class to provider a color for highlight a variable using one of the 'slice' actions
 * 
 * @see ForwardSliceAction
 * @see BackwardsSliceAction
 */
public class SliceHighlightColorProvider implements TokenHighlightColorProvider {

	private Set<Varnode> varnodes;
	private Varnode specialVn;
	private PcodeOp specialOp;
	private Color hlColor;
	private Color specialHlColor;

	SliceHighlightColorProvider(DecompilerPanel panel, Set<Varnode> varnodes, Varnode specialVn,
			PcodeOp specialOp) {
		this.varnodes = varnodes;
		this.specialVn = specialVn;
		this.specialOp = specialOp;

		hlColor = panel.getCurrentVariableHighlightColor();
		specialHlColor = panel.getSpecialHighlightColor();
	}

	@Override
	public Color getColor(ClangToken token) {

		Varnode vn = DecompilerUtils.getVarnodeRef(token);
		if (vn == null) {
			return null;
		}

		Color c = null;
		if (varnodes.contains(vn)) {
			c = hlColor;
		}

		if (specialOp == null) {
			return c;
		}

		// look for specific varnode to label with special color
		if (vn == specialVn && token.getPcodeOp() == specialOp) {
			c = specialHlColor;
		}
		return c;
	}
}
