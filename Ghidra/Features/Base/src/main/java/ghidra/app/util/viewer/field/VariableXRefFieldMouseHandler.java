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
package ghidra.app.util.viewer.field;

import java.util.*;

import ghidra.app.nav.Navigatable;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.*;

/**
 * A handler to process {@link VariableXRefFieldLocation} clicks.
 */
public class VariableXRefFieldMouseHandler extends XRefFieldMouseHandler {


	private final static Class<?>[] SUPPORTED_CLASSES = new Class<?>[] {
		VariableXRefFieldLocation.class, VariableXRefHeaderFieldLocation.class };

	@Override
	protected Address getToReferenceAddress(ProgramLocation programLocation, Program program) {
		Variable variable = ((VariableLocation) programLocation).getVariable();
		return variable.getMinAddress();
	}

	@Override
	protected Address getFromReferenceAddress(ProgramLocation programLocation) {
		return ((VariableXRefFieldLocation) programLocation).getRefAddress();
	}

	@Override
	protected ProgramLocation getReferredToLocation(Navigatable navigatable,
			ProgramLocation location) {
		VariableLocation variableLocation = (VariableLocation) location;
		Variable variable = variableLocation.getVariable();
		return new VariableNameFieldLocation(variable.getProgram(), variable, 0);
	}

	@Override
	protected int getIndex(ProgramLocation programLocation) {
		return ((VariableXRefFieldLocation) programLocation).getIndex();
	}

	/**
	 * @see XRefFieldMouseHandler#getSupportedProgramLocations()
	 */
	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}

	@Override
	protected boolean isXREFHeaderLocation(ProgramLocation location) {
		return location instanceof VariableXRefHeaderFieldLocation;
	}

	protected void showXRefDialog(Navigatable navigatable, ProgramLocation location,
			ServiceProvider serviceProvider) {
		TableService service = serviceProvider.getService(TableService.class);
		if (service == null) {
			return;
		}

		Address toAddress = location.getAddress();
		Program program = navigatable.getProgram();

		VariableLocation variableLocation = (VariableLocation) location;
		Variable variable = variableLocation.getVariable();

		List<Reference> refs = getReferences(variable);
		showReferenceTable(navigatable, serviceProvider, service, toAddress, program, refs);
	}

	private List<Reference> getReferences(Variable variable) {

		List<Reference> refs = new ArrayList<>();
		List<Reference> offcutRefs = new ArrayList<>();
		XReferenceUtil.getVariableRefs(variable, refs, offcutRefs);

		// Convert to a set before combining lists, to remove duplicates.
		Set<Reference> refsSet = new HashSet<Reference>(refs);
		Set<Reference> offcutRefsSet = new HashSet<Reference>(offcutRefs);
		refsSet.addAll(offcutRefsSet);

		return new ArrayList<>(refsSet);
	}
}
