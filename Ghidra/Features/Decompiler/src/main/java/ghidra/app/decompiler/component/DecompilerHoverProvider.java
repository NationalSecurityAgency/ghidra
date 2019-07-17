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
package ghidra.app.decompiler.component;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.core.hover.AbstractHoverProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;

public class DecompilerHoverProvider extends AbstractHoverProvider {

	public DecompilerHoverProvider() {
		super("DecompilerHoverProvider");
	}

	public void addHoverService(DecompilerHoverService hoverService) {
		super.addHoverService(hoverService);
	}

	public void removeHoverService(DecompilerHoverService hoverService) {
		super.removeHoverService(hoverService);
	}

	@Override
	protected ProgramLocation getHoverLocation(FieldLocation fieldLocation, Field field,
			Rectangle fieldBounds, MouseEvent event) {

		if (!(field instanceof ClangTextField)) {
			return null;
		}

		ClangTextField decompilerField = (ClangTextField) field;
		ClangToken token = decompilerField.getToken(fieldLocation);
		if (token instanceof ClangOpToken) {
			return null;
		}

		if (token instanceof ClangTypeToken) {
			ClangTypeToken typeToken = (ClangTypeToken) token;
			HighVariable hv = typeToken.getHighVariable();
			if (hv == null) {
				return null;
			}

			Address localAddr = hv.getRepresentative().getAddress();
			return new ProgramLocation(program, localAddr);
		}

		if (token.getMinAddress() == null) {
			return null;
		}

		Address reference = null;
		Varnode vn = token.getVarnode();
		if (vn != null) {
			HighVariable highVar = vn.getHigh();
			if (highVar instanceof HighGlobal) {
				reference = highVar.getRepresentative().getAddress();
			}
		}

		return new ProgramLocation(program, token.getMinAddress(), reference);
	}
}
