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

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.services.GoToService;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Playable;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.table.IncomingReferencesTableModel;
import ghidra.util.table.field.OutgoingReferenceEndpoint;

/**
 * A handler to process {@link OperandFieldLocation} mouse clicks.
 */
public class OperandFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] { OperandFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable navigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
		if (mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		OperandFieldLocation operandLocation = (OperandFieldLocation) location;
		if (mouseEvent.getClickCount() == 1) {
			return handleSingleClick(mouseEvent, navigatable, operandLocation);
		}

		if (mouseEvent.getClickCount() != 2) {
			return false;
		}

		Program program = navigatable.getProgram();
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(operandLocation.getAddress());
		if (codeUnit instanceof Data) {
			int[] componentPath = operandLocation.getComponentPath();
			if (componentPath != null && componentPath.length > 0) { // we're in a structure
				Data d = (Data) codeUnit;
				codeUnit = d.getComponent(componentPath);
			}
		}
		if (codeUnit == null) {
			return false;
		}
		return checkOperandFieldLocation(navigatable, codeUnit, operandLocation, serviceProvider);
	}

	private boolean handleSingleClick(MouseEvent mouseEvent, Navigatable navigatable,
			OperandFieldLocation location) {

		Program program = navigatable.getProgram();
		OperandFieldLocation operandLocation = location;
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(operandLocation.getAddress());
		if (codeUnit instanceof Data) {
			Data data = (Data) codeUnit;
			Object value = data.getValue();
			if (value instanceof Playable) {
				((Playable) value).clicked(mouseEvent);
				return true;
			}
		}

		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}

	// returns true if the given code unit is an operand field location and this handler knows
	// how to handle it
	private boolean checkOperandFieldLocation(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, ServiceProvider serviceProvider) {
		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}

		int opIndex = loc.getOperandIndex();
		if (checkVariableReference(navigatable, codeUnit, loc, goToService) ||
			checkExternalReference(navigatable, codeUnit, loc, goToService) ||
			checkMemRefs(navigatable, codeUnit, loc, serviceProvider)) {
			return true;
		}

		return checkOpObject(navigatable, codeUnit, opIndex, loc.getSubOperandIndex(), goToService);
	}

	private boolean checkExternalReference(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, GoToService goToService) {

		Address refAddr = loc.getRefAddress();
		if (refAddr == null || !refAddr.isExternalAddress()) {
			return checkExternalThunkFunctionReference(navigatable, codeUnit, loc, goToService);
		}

		Program program = codeUnit.getProgram();
		Symbol s = program.getSymbolTable().getPrimarySymbol(refAddr);
		if (s == null) {
			return false;
		}

		ExternalLocation extLoc = program.getExternalManager().getExternalLocation(s);
		return goToService.goToExternalLocation(extLoc, true);
	}

	private boolean checkExternalThunkFunctionReference(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, GoToService goToService) {

		Address refAddr = loc.getRefAddress();
		if (refAddr == null) {
			return false;
		}

		Program program = codeUnit.getProgram();
		Symbol s = program.getSymbolTable().getPrimarySymbol(refAddr);
		if (s == null) {
			return false;
		}

		SymbolType type = s.getSymbolType();
		if (type != SymbolType.FUNCTION) {
			return false;
		}

		Function refFunction = (Function) s.getObject();
		Function thunked = refFunction.getThunkedFunction(true);
		if (thunked == null) {
			return false;
		}

		if (thunked.getBody().contains(codeUnit.getAddress())) {
			// this handles the unlikely case where the user double-clicks a reference to a 
			// local thunk label--don't navigate externally
			return false;
		}

		Symbol thunkedSymbol = thunked.getSymbol();
		ExternalLocation extLoc = program.getExternalManager().getExternalLocation(thunkedSymbol);
		boolean success = goToService.goToExternalLocation(extLoc, true);
		return success;
	}

	private boolean checkVariableReference(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, GoToService goToService) {

		if (!(codeUnit instanceof Instruction)) {
			return false;
		}

		if (goToExplicitOperandVariable(navigatable, loc, goToService)) {
			return true;
		}

		Program p = codeUnit.getProgram();
		Address cuAddr = codeUnit.getMinAddress();
		Function function = p.getFunctionManager().getFunctionContaining(cuAddr);
		if (function == null) {
			return false;
		}

		if (goToRegisterVariable(navigatable, codeUnit, loc, goToService)) {
			return true;
		}

		Reference reference = codeUnit.getPrimaryReference(loc.getOperandIndex());
		if (reference == null) {
			return false;
		}

		Variable variable = p.getFunctionManager().getReferencedVariable(cuAddr,
			reference.getToAddress(), 0, reference.getReferenceType().isRead());
		if (variable != null) {
			ProgramLocation pl =
				new VariableNameFieldLocation(navigatable.getProgram(), variable, 0);
			goToService.goTo(navigatable, pl, navigatable.getProgram());
			return true;
		}

		if (reference.isStackReference()) {
			ProgramLocation pl = new FunctionSignatureFieldLocation(p, function.getEntryPoint(),
				null, 0, function.getPrototypeString(false, false));
			goToService.goTo(navigatable, pl, navigatable.getProgram());
			return true;
		}
		return false;
	}

	private boolean goToRegisterVariable(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, GoToService goToService) {

		Address refAddr = loc.getRefAddress();
		Address cuAddr = codeUnit.getMinAddress();
		if (refAddr == null || refAddr.isStackAddress()) {
			return false;
		}

		Program p = codeUnit.getProgram();
		Register reg = p.getRegister(refAddr, 1);
		if (reg == null) {
			return false;
		}

		Variable variable = p.getFunctionManager().getReferencedVariable(cuAddr, refAddr,
			reg.getMinimumByteSize(), !isWrite((Instruction) codeUnit, loc.getOperandIndex(), reg));
		if (variable == null) {
			return false;
		}

		ProgramLocation pl = new VariableNameFieldLocation(navigatable.getProgram(), variable, 0);
		goToService.goTo(navigatable, pl, navigatable.getProgram());
		return true;
	}

	/**
	 * Navigate to the variable, when directly supplied by the field location
	 * 
	 * @param navigatable the navigatable to which we should navigate
	 * @param loc the source location
	 * @param goToService the GoTo service
	 * @return true if we decide to attempt navigation
	 */
	private boolean goToExplicitOperandVariable(Navigatable navigatable, OperandFieldLocation loc,
			GoToService goToService) {

		VariableOffset variableOffset = loc.getVariableOffset();
		if (variableOffset != null) {
			Variable variable = variableOffset.getVariable();
			if (variable != null) {
				goToService.goTo(navigatable,
					new VariableNameFieldLocation(navigatable.getProgram(), variable, 0),
					navigatable.getProgram());
				return true;
			}
		}
		return false;
	}

	private boolean isWrite(Instruction inst, int operandIndex, Register reg) {
		for (Object obj : inst.getResultObjects()) {
			if (obj == reg) {
				return true;
			}
		}
		return false;
	}

	private boolean checkMemRefs(Navigatable navigatable, CodeUnit codeUnit,
			OperandFieldLocation loc, ServiceProvider serviceProvider) {

		Address refAddr = loc.getRefAddress();
		if (refAddr == null || !refAddr.isMemoryAddress()) {
			return false;
		}

		Reference[] refs = codeUnit.getOperandReferences(loc.getOperandIndex());
		Address[] addrs = getAddressesForReferences(refs, codeUnit, serviceProvider);
		if (addrs.length == 0) {
			return false;
		}

		if (addrs.length > 1) {
			List<OutgoingReferenceEndpoint> outgoingReferences = new ArrayList<>();
			for (int i = 0; i < refs.length; i++) {
				Reference ref = refs[i];
				boolean offcut = ReferenceUtils.isOffcut(codeUnit.getProgram(), ref.getToAddress());
				outgoingReferences.add(new OutgoingReferenceEndpoint(ref, addrs[i], offcut));
			}

			IncomingReferencesTableModel model = new IncomingReferencesTableModel("Operand",
				serviceProvider, codeUnit.getProgram(), outgoingReferences, null);
			TableService service = serviceProvider.getService(TableService.class);

			Navigatable nav = NavigationUtils.getActiveNavigatable();
			String addressString = codeUnit.getMinAddress().toString();
			service.showTable("Operand References for " + addressString, "Operands", model,
				"References", nav);
			return true;
		}

		// 1 address found
		Address gotoAddr = addrs[0];
		if (gotoAddr == null) {
			return false;
		}

		GoToService goToService = serviceProvider.getService(GoToService.class);
		return goToService.goTo(navigatable, codeUnit.getProgram(), gotoAddr,
			codeUnit.getAddress());
	}

	private Address[] getAddressesForReferences(Reference[] references, CodeUnit codeUnit,
			ServiceProvider serviceProvider) {
		Address[] addresses = new Address[references.length];
		for (int i = 0; i < references.length; i++) {
			addresses[i] = getAddressForReference(codeUnit, references[i], serviceProvider,
				references.length != 1); // GoToQuery unable to handle external addresses
		}
		return addresses;
	}

	private Address getAddressForReference(CodeUnit codeUnit, Reference reference,
			ServiceProvider serviceProvider, boolean skipExternal) {
		Address address = reference.getToAddress();
		RefType refType = reference.getReferenceType();
		if (!refType.isIndirect()) {
			return address;
		}

		Program program = codeUnit.getProgram();
		Data data = program.getListing().getDefinedDataAt(address);
		Address indirectAddrress = null;
		if (data != null) {
			if (data.isPointer()) {
				Reference ref = data.getPrimaryReference(0);
				indirectAddrress = ref != null ? ref.getToAddress() : (Address) data.getValue();
			}
		}
		else {
			PseudoDisassembler pdis = new PseudoDisassembler(program);
			indirectAddrress = pdis.getIndirectAddr(address);
		}

		if (indirectAddrress != null && (!indirectAddrress.isExternalAddress() || !skipExternal) &&
			followIndirectReference(serviceProvider, indirectAddrress, program)) {
			return indirectAddrress;
		}
		return address;
	}

	private boolean followIndirectReference(ServiceProvider serviceProvider,
			Address indirectAddrress, Program program) {
		OptionsService optionsService = serviceProvider.getService(OptionsService.class);
		if (optionsService == null) {
			return false;
		}

		NavigationOptions navOptions = new NavigationOptions(optionsService);
		try {
			if (!navOptions.isFollowIndirectionEnabled()) {
				return false;
			}
			if (indirectAddrress.isExternalAddress()) {
				return navOptions.isGotoExternalProgramEnabled();
			}
			return program.getMemory().contains(indirectAddrress);
		}
		finally {
			navOptions.dispose();
		}
	}

	private boolean checkOpObject(Navigatable navigatable, CodeUnit codeUnit, int opIndex,
			int subOpIndex, GoToService goToService) {

		if (codeUnit instanceof Data) {
			return handleData((Data) codeUnit, navigatable, goToService);
		}

		if (!(codeUnit instanceof Instruction) || subOpIndex < 0) {
			return false;
		}

		List<?> opObjects = ((Instruction) codeUnit).getDefaultOperandRepresentationList(opIndex);
		if (opObjects == null || opObjects.size() <= subOpIndex) {
			return false;
		}

		Address goToAddr = getAddressForOpObject(opObjects.get(subOpIndex), codeUnit);
		if (goToAddr != null && goToService.goTo(navigatable, goToAddr)) {
			return true;
		}
		return false;
	}

	private boolean handleData(Data data, Navigatable navigatable, GoToService goToService) {
		Object value = data.getValue();
		Address address = null;
		if (value instanceof Address) {
			address = (Address) value;
		}
		else if (value instanceof Scalar) {
			Scalar scalar = (Scalar) value;
			address = getAddressFromScalar(data, scalar);
		}

		if (address == null) {
			return false;
		}

		return goToService.goTo(navigatable, address);
	}

	private Address getAddressForOpObject(Object opObject, CodeUnit codeUnit) {
		if (opObject instanceof Address) {
			return (Address) opObject;
		}

		if (opObject instanceof Scalar) {
			Scalar scalar = (Scalar) opObject;
			return getAddressFromScalar(codeUnit, scalar);
		}

		return null;
	}

	private Address getAddressFromScalar(CodeUnit codeUnit, Scalar scalar) {
		Address minAddress = codeUnit.getMinAddress();
		Address address = null;
		try {
			address = minAddress.getNewAddress(scalar.getUnsignedValue(), true);
		}
		catch (Exception e) {
			// ignore
		}
		Program program = codeUnit.getProgram();
		if (address == null || !program.getMemory().contains(address)) {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			try {
				address = space.getAddress(scalar.getUnsignedValue(), true);
			}
			catch (Exception e) {
				// ignore
			}
		}
		return address;
	}
}
