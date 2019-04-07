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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.navigation.FunctionUtils;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.UndefinedFunction;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// treats all such locations as function name clicks
class FunctionSignatureFieldLocationDescriptor extends LocationDescriptor {
	protected Function function;

	FunctionSignatureFieldLocationDescriptor(FunctionLocation location, Program program) {
		super(location, program);

		validate(location);

		programLocation = location;
		this.program = program;

		FunctionManager functionManager = program.getFunctionManager();
		function = functionManager.getFunctionAt(location.getFunctionAddress());

		if (function == null) {
			// Something wacky has happened--like the function for this location was deleted by
			// a background thread.  We don't want NPEs, so do something reasonable.
			function = new UndefinedFunction(program, location.getFunctionAddress());
		}

		init();
	}

	protected void validate(FunctionLocation location) {
		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null ProgramLocation");
		}
	}

	// allows subclasses to perform custom initialization
	protected void init() {
		validate((FunctionSignatureFieldLocation) programLocation);
		homeAddress = function.getEntryPoint();
		label = function.getName();
	}

	@Override
	protected boolean domainObjectChanged(DomainObjectChangedEvent changeEvent) {
		if (super.domainObjectChanged(changeEvent)) {
			return true;
		}

		for (int i = 0; i < changeEvent.numRecords(); i++) {
			DomainObjectChangeRecord domainObjectRecord = changeEvent.getChangeRecord(i);
			int eventType = domainObjectRecord.getEventType();

			if (domainObjectRecord instanceof ProgramChangeRecord) {
				ProgramChangeRecord programChangeRecord = (ProgramChangeRecord) domainObjectRecord;
				if (eventType == ChangeManager.DOCR_FUNCTION_REMOVED) {
					Address effectedEntryPoint = programChangeRecord.getStart();
					if (effectedEntryPoint.equals(function.getEntryPoint())) {
						checkForAddressChange(domainObjectRecord);
						return true;
					}
				}
				else if (eventType == ChangeManager.DOCR_MEM_REFERENCE_REMOVED) {
					Address addr = programChangeRecord.getStart();
					Function functionContaining =
						program.getFunctionManager().getFunctionContaining(addr);
					if (functionContaining != null) {
						Address containingEntryPoint = functionContaining.getEntryPoint();
						if (containingEntryPoint.equals(function.getEntryPoint())) {
							checkForAddressChange(domainObjectRecord);
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		ReferenceUtils.getReferences(accumulator, programLocation, monitor);
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			!currentAddress.equals(homeAddress)) {
			String functionNameString = getFunctionNameString(text);
			int offset = text.indexOf(functionNameString);
			if (offset >= 0) {
				int length = offset + functionNameString.length() - 1;
				return new Highlight[] { new Highlight(offset, length, highlightColor) };
			}
		}
		else if (FunctionSignatureFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			FieldStringInfo nameStringInfo =
				FunctionUtils.getFunctionNameStringInfo(function, text);
			String functionName = nameStringInfo.getFieldString();
			int offset = nameStringInfo.getOffset();
			return new Highlight[] {
				new Highlight(offset, functionName.length() + offset - 1, highlightColor) };
		}

		return EMPTY_HIGHLIGHTS;
	}

	private String getFunctionNameString(String text) {
		String functionName = function.getName(true);
		if (text.indexOf(functionName) != -1) {
			return functionName;
		}
		return function.getName();
	}

	@Override
	// overridden to take us to the function part from whence we came (not the address)
	ProgramLocation getHomeLocation() {
		return programLocation;
	}
}
