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
package ghidra.pcode.emu.sys;

import java.util.Arrays;
import java.util.List;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.sys.EmuSyscallLibrary.EmuSyscallDefinition;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;

/**
 * A system call that is defined by delegating to a p-code userop
 * 
 * <p>
 * This is essentially a wrapper of the p-code userop. Knowing the number of inputs to the userop
 * and by applying the calling conventions of the platform, the wrapper aliases each parameter's
 * storage to its respective parameter of the userop. The userop's output is also aliased to the
 * system call's return storage, again as defined by the platform's conventions.
 * 
 * @see AnnotatedEmuSyscallUseropLibrary
 * @param <T> the type of values processed by the library
 */
public class UseropEmuSyscallDefinition<T> implements EmuSyscallDefinition<T> {

	/**
	 * Obtain the program's "pointer" data type, throwing an exception if absent
	 * 
	 * @param program the program
	 * @return the "pointer" data type
	 */
	protected static DataType requirePointerDataType(Program program) {
		DataType dtPointer = program.getDataTypeManager().getDataType("/pointer");
		if (dtPointer == null) {
			throw new IllegalArgumentException("No 'pointer' data type in " + program);
		}
		return dtPointer;
	}

	protected final PcodeUseropDefinition<T> opdef;
	protected final List<Varnode> inVars;
	protected final Varnode outVar;

	/**
	 * Construct a syscall definition
	 * 
	 * @see AnnotatedEmuSyscallUseropLibrary
	 * @param opdef the wrapped userop definition
	 * @param program the program, used for storage computation
	 * @param convention the "syscall" calling convention
	 * @param dtMachineWord the "pointer" data type
	 */
	public UseropEmuSyscallDefinition(PcodeUseropDefinition<T> opdef, Program program,
			PrototypeModel convention, DataType dtMachineWord) {
		this.opdef = opdef;

		// getStorageLocations needs return(1) + parameters(n)
		int inputCount = opdef.getInputCount();
		if (inputCount < 0) {
			throw new IllegalArgumentException("Variadic sleigh userop " + opdef.getName() +
				" cannot be used as a syscall");
		}
		DataType[] locs = new DataType[inputCount + 1];
		for (int i = 0; i < locs.length; i++) {
			locs[i] = dtMachineWord;
		}
		VariableStorage[] vss = convention.getStorageLocations(program, locs, false);

		outVar = getSingleVnStorage(vss[0]);
		inVars = Arrays.asList(new Varnode[inputCount]);
		for (int i = 0; i < inputCount; i++) {
			inVars.set(i, getSingleVnStorage(vss[i + 1]));
		}
	}

	/**
	 * Assert variable storage is a single varnode, and get that varnode
	 * 
	 * @param vs the storage
	 * @return the single varnode
	 */
	protected Varnode getSingleVnStorage(VariableStorage vs) {
		Varnode[] vns = vs.getVarnodes();
		if (vns.length != 1) {
			Unfinished.TODO();
		}
		return vns[0];
	}

	@Override
	public void invoke(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library) {
		try {
			opdef.execute(executor, library, outVar, inVars);
		}
		catch (PcodeExecutionException e) {
			throw e;
		}
		catch (Throwable e) {
			throw new EmuSystemException("Error during syscall", null, e);
		}
	}
}
