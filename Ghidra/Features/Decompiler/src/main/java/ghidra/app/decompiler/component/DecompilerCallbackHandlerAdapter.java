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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import utility.function.Callback;

public class DecompilerCallbackHandlerAdapter implements DecompilerCallbackHandler {

	@Override
	public void decompileDataChanged(DecompileData decompileData) {
		// stub
	}

	@Override
	public void contextChanged() {
		// stub
	}

	@Override
	public void setStatusMessage(String message) {
		// stub
	}

	@Override
	public void locationChanged(ProgramLocation programLocation) {
		// stub
	}

	@Override
	public void selectionChanged(ProgramSelection programSelection) {
		// stub
	}

	@Override
	public void annotationClicked(AnnotatedTextFieldElement annotation, boolean newWindow) {
		// stub
	}

	@Override
	public void goToLabel(String labelName, boolean newWindow) {
		// stub
	}

	@Override
	public void goToAddress(Address addr, boolean newWindow) {
		// stub
	}

	@Override
	public void goToScalar(long value, boolean newWindow) {
		// stub
	}

	@Override
	public void exportLocation() {
		// stub
	}

	@Override
	public void goToFunction(Function function, boolean newWindow) {
		// stub
	}

	@Override
	public void doWhenNotBusy(Callback c) {
		// stub
	}

}
