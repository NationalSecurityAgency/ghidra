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
package ghidra.app.util.bin.format.pdb;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.bin.format.pdb.PdbParser.PdbXmlMember;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyStackVariables {
	private PdbParser pdbParser;
	private XmlPullParser xmlParser;
	private Function function;

	ApplyStackVariables(PdbParser pdbParser, XmlPullParser xmlParser, Function function) {
		this.pdbParser = pdbParser;
		this.xmlParser = xmlParser;
		this.function = function;
	}

	private boolean isParameterRecoverySupported() {
		// NOTE: this is a temporary solution to the lack of proper register
		// variable support
		Program p = function.getProgram();
		if (p.getDefaultPointerSize() != 32) {
			return false;
		}
		return "x86".equals(p.getLanguage().getProcessor().toString());
	}

	void applyTo(TaskMonitor monitor, MessageLog log) throws CancelledException {
		int frameBase = getFrameBaseOffset(monitor);

		boolean skipParameters = !isParameterRecoverySupported();

		while (xmlParser.hasNext()) {
			monitor.checkCanceled();

			XmlElement elem = xmlParser.peek();
			if (elem.isEnd() && elem.getName().equals("function")) {
				break;
			}
			else if (elem.isStart() && elem.getName().equals("line_number")) {
				break;
			}
			elem = xmlParser.next();//stack variable number start tag

			PdbXmlMember member = pdbParser.getPdbXmlMember(elem);

			if (PdbKind.STATIC_LOCAL == member.kind) {
				xmlParser.next();//stack variable number end tag
				continue;
			}

			DataType dt = getDataType(member, log);
			if (dt == null) {
				xmlParser.next();//stack variable number end tag
				continue;
			}

			if (PdbKind.OBJECT_POINTER == member.kind) {
				if (skipParameters) {
					xmlParser.next();
					continue;
				}
				createRegisterParameter(member.memberName, dt, log);
			}
			else if (PdbKind.PARAMETER == member.kind) {
				if (skipParameters) {
					xmlParser.next();
					continue;
				}
				createStackVariable(member.memberName, frameBase + member.memberOffset, dt, log);
			}
			else if (PdbKind.LOCAL == member.kind) {
				int stackOffset = frameBase + member.memberOffset;
				if (skipParameters && function.getStackFrame().isParameterOffset(stackOffset)) {
					xmlParser.next();
					continue;
				}
				createStackVariable(member.memberName, stackOffset, dt, log);
			}

			xmlParser.next();//stack variable number end tag
		}
	}

	/**
	 * Get the stack offset after it settles down.
	 * 
	 * @param monitor
	 * @return stack offset that stack variables will be relative to.
	 * @throws CancelledException 
	 */
	private int getFrameBaseOffset(TaskMonitor monitor) throws CancelledException {

		int retAddrSize = function.getProgram().getDefaultPointerSize();

		if (retAddrSize != 8) {
			// don't do this for 32 bit.
			return -retAddrSize;  // 32 bit has a -4 byte offset
		}

		Register frameReg = function.getProgram().getCompilerSpec().getStackPointer();
		Address entryAddr = function.getEntryPoint();
		AddressSet scopeSet = new AddressSet();
		scopeSet.addRange(entryAddr, entryAddr.add(64));
		CallDepthChangeInfo valueChange =
			new CallDepthChangeInfo(function, scopeSet, frameReg, monitor);
		InstructionIterator instructions =
			function.getProgram().getListing().getInstructions(scopeSet, true);
		int max = 0;
		while (instructions.hasNext()) {
			monitor.checkCanceled();
			Instruction next = instructions.next();
			int newValue = valueChange.getDepth(next.getMinAddress());
			if (newValue < -(20 * 1024) || newValue > (20 * 1024)) {
				continue;
			}
			if (Math.abs(newValue) > Math.abs(max)) {
				max = newValue;
			}
		}
		return max;
	}

	private Variable createRegisterParameter(String name, DataType dt, MessageLog log) {
		Register ecx = function.getProgram().getLanguage().getRegister("ECX");
		try {
			Parameter[] parameters =
				function.getParameters(VariableFilter.REGISTER_VARIABLE_FILTER);
			for (Parameter parameter : parameters) {
				if (parameter.getRegister().equals(ecx)) {
					parameter.setDataType(dt, false, true, SourceType.ANALYSIS);
					try {
						parameter.setName(name, SourceType.IMPORTED);
					}
					catch (DuplicateNameException e) {
					}
					return parameter;
				}
			}

			Variable variable = new LocalVariableImpl(name, 0, dt, ecx, function.getProgram());
			try {
				return function.addParameter(variable, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				variable.setName(variable + "_" + ecx.getName(), SourceType.IMPORTED);
				return function.addParameter(variable, SourceType.IMPORTED);
			}
		}
		catch (Exception e) {
			log.appendMsg("PDB",
				"Unable to create register variable " + name + " in " + function.getName());
		}
		return null;
	}

	private Variable createStackVariable(final String name, final int offset, DataType dt,
			MessageLog log) {
		StackFrame stackFrame = function.getStackFrame();
		Variable variable = stackFrame.getVariableContaining(offset);
		try {
			if (variable == null || variable.getStackOffset() != offset) {
				if (variable != null) {
					stackFrame.clearVariable(variable.getStackOffset());
				}
				try {
					variable = stackFrame.createVariable(name, offset, dt, SourceType.IMPORTED);
				}
				catch (DuplicateNameException e) {
					variable = stackFrame.createVariable(name + "@" + Integer.toHexString(offset),
						offset, dt, SourceType.IMPORTED);
				}
			}
			else {
				variable.setDataType(dt, false, true, SourceType.ANALYSIS);
				try {
					variable.setName(name, SourceType.IMPORTED);
				}
				catch (DuplicateNameException e) {
					variable.setName(name + "@" + Integer.toHexString(offset), SourceType.IMPORTED);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("PDB", "Unable to create stack variable " + name + " at offset " +
				offset + " in " + function.getName());
		}
		return variable;
	}

	private DataType getDataType(PdbXmlMember member, MessageLog log) throws CancelledException {
		WrappedDataType wrappedDataType = pdbParser.findDataType(member.memberDataTypeName);
		if (wrappedDataType == null) {
			log.appendMsg("PDB", "Failed to resolve data type for " + member.kind + ": " +
				member.memberDataTypeName);
			return null;
		}
		if (wrappedDataType.isZeroLengthArray()) {
			log.appendMsg("PDB", "Zero length array not supported for for " + member.kind + ": " +
				member.memberDataTypeName);
			return null;
		}
		return wrappedDataType.getDataType();
	}

}
