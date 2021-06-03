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

import java.awt.BorderLayout;

import javax.swing.JPanel;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.core.decompile.DecompilerClipboardProvider;
import ghidra.app.util.viewer.listingpanel.ProgramLocationListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import utility.function.Callback;

public class CDisplayPanel extends JPanel implements DecompilerCallbackHandler {

	private DecompilerController controller;
	private DecompileResultsListener listener;

	private ProgramLocationListener locationListener;

	public CDisplayPanel(DecompileResultsListener listener) {
		this(new DecompileOptions(), listener);
	}

	public CDisplayPanel(DecompileOptions decompileOptions, DecompileResultsListener listener) {
		super(new BorderLayout());
		this.listener = listener;
		controller = new ExtendedDecompilerController(this, decompileOptions, null);
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		add(decompilerPanel);
	}

	public void setProgramLocationListener(ProgramLocationListener locationListener) {
		this.locationListener = locationListener;
	}

	class ExtendedDecompilerController extends DecompilerController {

		public ExtendedDecompilerController(DecompilerCallbackHandler handler,
				DecompileOptions options, DecompilerClipboardProvider clipboard) {
			super(handler, options, clipboard);
		}

		@Override
		public void setDecompileData(DecompileData decompileData) {
			super.setDecompileData(decompileData);
			if (listener != null) {
				listener.setDecompileData(decompileData);
			}
		}

		@Override
		public void dispose() {
			listener = null;
			super.dispose();
		}
	}

	public DecompilerPanel getDecompilerPanel() {
		return controller.getDecompilerPanel();
	}

	public void showFunction(Program program, Address address) {
		controller.display(program, new ProgramLocation(program, address),
			new ViewerPosition(0, 0, 0));
	}

	public void showFunction(Function function) {
		if (function == null) {
			clearAndShowMessage("No Function");
			return;
		}
		if (function.isExternal()) {
			clearAndShowMessage("\"" + function.getName(true) + "\" is an external function.");
			return;
		}
		Program program = function.getProgram();
		Address entry = function.getEntryPoint();
		ProgramLocation location = new ProgramLocation(program, entry);
		controller.display(program, location, new ViewerPosition(0, 0, 0));
	}

	@Override
	public void contextChanged() {
		// stub
	}

	@Override
	public void decompileDataChanged(DecompileData decompileData) {
		// stub
	}

	@Override
	public void exportLocation() {
		// stub
	}

	@Override
	public void annotationClicked(AnnotatedTextFieldElement annotation, boolean newWindow) {
		// stub
	}

	@Override
	public void goToAddress(Address addr, boolean newWindow) {
		// stub
	}

	@Override
	public void goToLabel(String labelName, boolean newWindow) {
		// stub
	}

	@Override
	public void goToScalar(long value, boolean newWindow) {
		// stub
	}

	@Override
	public void goToFunction(Function function, boolean newWindow) {
		// stub
	}

	@Override
	public void locationChanged(ProgramLocation programLocation) {
		if (locationListener == null) {
			return;
		}
		this.locationListener.programLocationChanged(programLocation, null);
	}

	@Override
	public void selectionChanged(ProgramSelection programSelection) {
		// stub
	}

	@Override
	public void setStatusMessage(String message) {
		// stub
	}

	@Override
	public void doWheNotBusy(Callback c) {
		// stub 
	}

	public void clearAndShowMessage(String message) {
		controller.setDecompileData(new EmptyDecompileData(message));
		paintImmediately(getBounds());
	}

	public void setMouseNavigationEnabled(boolean enabled) {
		controller.setMouseNavigationEnabled(enabled);
	}

	public void dispose() {
		controller.dispose();
	}
}
