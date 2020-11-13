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
package ghidra.app.cmd.function;

import java.util.*;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Command for Creating a function at an address.  It will copy off the
 * parameters used to create the function (Selection or just an address) and
 * create the function on redo and clear on undo.
 */
public class CreateFunctionCmd extends BackgroundCommand {

	private AddressSetView origEntries;
	private AddressSetView origBody;
	private Program program;
	private String name;
	private Function newFunc;
	private SourceType source;
	private boolean findEntryPoint = false;
	private boolean recreateFunction = false;
	private List<Address> referringThunkAddresses;

	/**
	 * Constructs a new command for creating a function.  The default name
	 * for a function is the name associated with the current primary symbol which
	 * will be removed.
	 * @param name function name or null for default name.
	 * @param entries the entry points at which to create functions.
	 * @param body set of addresses to associated with the function to be created.
	 * The addresses must not already be included in the body of any existing function.
	 * @param source the source of this function
	 * @param findEntryPoint true if the entry point should be computed (entry could be in the middle of a function)
	 * @param recreateFunction true if the function body should be recreated even if the function exists.
	 */
	public CreateFunctionCmd(String name, AddressSetView entries, AddressSetView body,
			SourceType source, boolean findEntryPoint, boolean recreateFunction) {
		super("Create Function", true, true, false);
		this.origEntries = entries;
		this.origBody = body;
		this.name = name;
		this.source = source;
		this.findEntryPoint = findEntryPoint;
		this.recreateFunction = recreateFunction;
	}

	/**
	 * Constructs a new command for creating a function.  The default name
	 * for a function is the name associated with the current primary symbol which
	 * will be removed.
	 * @param name function name or null for default name.
	 * @param entry entry point address for the function to be created.
	 * @param body set of addresses to associated with the function to be created.
	 * The addresses must not already be included in the body of any existing function.
	 * @param source the source of this function
	 * @param findEntryPoint true if the entry point should be computed (entry could be in the middle of a function)
	 * @param recreateFunction true if the function body should be recreated even if the function exists.
	 */
	public CreateFunctionCmd(String name, Address entry, AddressSetView body, SourceType source,
			boolean findEntryPoint, boolean recreateFunction) {
		this(name, new AddressSet(entry, entry), body, source, findEntryPoint, recreateFunction);
	}

	/**
	 * Constructs a new command for creating functions that automatically computes
	 * the body of each function.
	 * @param entries the entry points at which to create functions.
	 */
	public CreateFunctionCmd(AddressSetView entries, boolean findEntryPoint) {
		this(null, entries, null, SourceType.DEFAULT, findEntryPoint, false);
	}

	/**
	 * Constructs a new command for creating functions that automatically computes
	 * the body of each function.
	 * @param entries the entry points at which to create functions.
	 */
	public CreateFunctionCmd(AddressSetView entries) {
		this(null, entries, null, SourceType.DEFAULT, false, false);
	}

	/**
	 * Constructs a new command for creating functions that automatically computes
	 * the body of each function.
	 * @param entries the entry points at which to create functions.
	 */
	public CreateFunctionCmd(AddressSetView entries, SourceType source) {
		this(null, entries, null, source, false, false);
	}

	public CreateFunctionCmd(String name, Address entry, AddressSetView body, SourceType source) {
		this(name, entry, body, source, false, false);
	}

	/**
	 * Constructs a new command for creating a function that automatically computes
	 * the body of the function.
	 * @param entry the entry point at which to create a function.
	 * @param referringThunkAddresses provides a list of referring Thunk functions which lead to
	 * the creation of the function at entry.
	 */
	CreateFunctionCmd(Address entry, List<Address> referringThunkAddresses) {
		this(entry);
		this.referringThunkAddresses = referringThunkAddresses;
	}

	/**
	 * Constructs a new command for creating a function that automatically computes
	 * the body of the function.
	 * @param entry the entry point at which to create a function.
	 */
	public CreateFunctionCmd(Address entry) {
		this(null, entry, null, SourceType.DEFAULT);
	}

	public CreateFunctionCmd(Address entry, boolean findEntryPoint) {
		this(null, entry, null, SourceType.DEFAULT, findEntryPoint, false);
	}

	/**
	 *
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		Namespace globalNameSpace = program.getGlobalNamespace();

		int functionsCreated = 0;
		int count = 0;

		monitor.initialize(origEntries.getNumAddresses());

		CodeBlockModel functionModel = null;
		AddressIterator iter = origEntries.getAddresses(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			monitor.setProgress(++count);
			SourceType tmpSource = source;
			Address origEntry = iter.next();
			String funcName = name;

			try {
				if (origEntry.isExternalAddress()) {
					Symbol oldSym = program.getSymbolTable().getPrimarySymbol(origEntry);
					if (oldSym == null) {
						// skip bad external address
						continue;
					}
					Function extFunc;
					Object symObj = oldSym.getObject();
					if (symObj instanceof Function) {
						extFunc = (Function) symObj;
					}
					else if (symObj instanceof ExternalLocation) {
						extFunc = ((ExternalLocation) symObj).createFunction();
					}
					else {
						Msg.error(this, "Unexpected external symbol object: " + obj.getClass());
						continue;
					}
					if (funcName != null) {
						monitor.setMessage("Function " + funcName);
						extFunc.setName(funcName, source);
					}
				}
				else {
					Namespace nameSpace = globalNameSpace;
					if (funcName == null) {
						Symbol oldSym = program.getSymbolTable().getPrimarySymbol(origEntry);
						if (oldSym != null && oldSym.getSource() != SourceType.DEFAULT) {
							funcName = oldSym.getName();
							tmpSource = oldSym.getSource();
							Namespace oldParentNamespace = oldSym.getParentNamespace();
							// A function can't have another function as its parent.
							if (oldParentNamespace.getSymbol().getSymbolType() != SymbolType.FUNCTION) {
								nameSpace = oldParentNamespace;
							}
						}
						else {
							funcName = SymbolUtilities.getDefaultFunctionName(origEntry);
							tmpSource = SourceType.DEFAULT;
						}
					}

					monitor.setMessage("Function " + funcName);

					if (functionModel == null) {
						functionModel = new PartitionCodeSubModel(program);
					}
// TODO: What if function already exists ??
					if (createFunction(monitor, funcName, functionModel, nameSpace, origEntry,
						origBody, tmpSource)) {
						functionsCreated++;
					}
					else {
						setStatusMsg("Unable to create function at " + origEntry);
					}
				}
			}
			catch (CancelledException e) {
				// TODO: Should we roll-back due to half-baked function bodies??
				// throw new RollbackException("Function creation was canceled");
			}
			catch (Exception e) {
				String errMsg = e.getMessage();
				if (errMsg == null) {
					errMsg = e.toString();
				}
				setStatusMsg(errMsg);
			}
		}

		if (functionsCreated == origEntries.getNumAddresses()) {
			return true;
		}
		return false;
	}

	/**
	 * Returns function if create command was successful
	 */
	public Function getFunction() {
		return newFunc;
	}

	/**
	 * Creates a function in the program.
	 *
	 * @param entry
	 *            The address of the entry point for the new function
	 * @param body
	 *            The address set containing all the addresses to be included in
	 *            the body of the new function.
	 * @param nameSource
	 *            the source of this function's name
	 * @throws OverlappingFunctionException
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	private boolean createFunction(TaskMonitor monitor, String funcName,
			CodeBlockModel functionModel, Namespace nameSpace, Address entry, AddressSetView body,
			SourceType nameSource) throws DuplicateNameException, InvalidInputException,
			OverlappingFunctionException, CancelledException {

		FunctionManager functionMgr = program.getFunctionManager();

		// if the entry point is unknown, and just have a location in the body
		//    try to find the entry point (must wander into an existing function
		if (this.findEntryPoint) {
			// if we are already in a function, then no need to find the entry
			Function functionContaining = functionMgr.getFunctionContaining(entry);
			if (functionContaining != null) {
				// if we are not recreating the function,
				//  then don't continue because there is already a function here.
				if (!recreateFunction) {
					long bodySize = functionContaining.getBody().getNumAddresses();
					if (bodySize != 1) {
						return false;
					}
				}

				// if the function containing this entry does not start at this address
				if (!functionContaining.getEntryPoint().equals(entry)) {
					entry = findFunctionEntry(entry);
				}
			}
			if (entry == null) {
				return false;
			}
			if (origBody != null && !origBody.isEmpty()) {
				Function func = program.getFunctionManager().getFunctionContaining(entry);
				if (func == null) {
					return false;
				}
				try {
					func.setBody(origBody); // trigger analysis
					return true;
				}
				catch (OverlappingFunctionException e) {
					// don't care about overlapping functions
				}
			}
			if (fixupFunctionBody(program, program.getListing().getInstructionAt(entry), monitor)) {
				return true;
			}
		}

		Function existingFunction = functionMgr.getFunctionAt(entry);

		// if there is an existing function handle necessary changes
		if (existingFunction != null) {
			return handleExistingFunction(monitor, entry, existingFunction);
		}

		// if the body is undefined, figure it out
		// get the function body JUST by following flow
		body = (body == null ? getFunctionBody(program, entry, false, monitor) : body);

		// subtract out any existing functions that overlap the body
		AddressSetView oldbody = body;
		body = removeExistingFunctionsFromBody(entry, body, monitor);
		if (body == null) {
			return false;
		}

		Map<Function, AddressSetView> bodyChangeMap = new HashMap<>();
		// If I ain't got nobody left after extracting overlapping functions
		if (body.isEmpty()) {
			// try subtracting this body from existing functions
			//   need to compute a bodyChangeMap if affecting other functions
			//   in case creation of this function fails
			body = subtractBodyFromExisting(entry, oldbody, bodyChangeMap, monitor);
		}

		return createFunction(nameSpace, funcName, entry, body, nameSource, bodyChangeMap, monitor);
	}

	/**
	 * create the function, undoing any changes to other functions bodies if the function creation fails
	 *
	 * @param nameSpace - functions namespace
	 * @param funcName - functions name
	 * @param entry - entry point of function
	 * @param body - body of function
	 * @param nameSource - source of the name
	 * @param bodyChangeMap - change map to restore other affected functions bodies if this fails
	 * @param monitor
	 * @return
	 * @throws OverlappingFunctionException
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private boolean createFunction(Namespace nameSpace, String funcName, Address entry,
			AddressSetView body, SourceType nameSource, Map<Function, AddressSetView> bodyChangeMap,
			TaskMonitor monitor)
			throws OverlappingFunctionException, DuplicateNameException, InvalidInputException {

		Listing listing = program.getListing();

		// See if there is a codeunit at the function entry point
		// don't allow creation of a function if no CU there.
		CodeUnit cu = listing.getCodeUnitAt(entry);
		if (cu == null) {
			return false;
		}
		try {
			// check for a thunk first
			if (resolveThunk(entry, body, monitor)) {
				return true;
			}
			if (referringThunkAddresses != null) {
				for (Address addr : referringThunkAddresses) {
					if (body.contains(addr)) {
						Msg.error(this, "Failed to create function at " + entry +
							" since its body contains referring thunk at " + addr);
						return false;
					}
				}
			}
			newFunc = listing.createFunction(funcName, nameSpace, entry, body, nameSource);
		}
		catch (InvalidInputException e) {
			restoreOriginalBodies(bodyChangeMap);
			throw e;
		}

		return true;
	}

	/**
	 * subtract this functions entire body from existing functions
	 *
	 * @param entry - entry point of new function
	 * @param body - new functions body
	 * @param bodyChangeMap - map of functions that have their bodies changed by creating this function
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 * @throws OverlappingFunctionException
	 */
	private AddressSetView subtractBodyFromExisting(Address entry, AddressSetView body,
			Map<Function, AddressSetView> bodyChangeMap, TaskMonitor monitor)
			throws CancelledException, OverlappingFunctionException {
		Iterator<Function> iter = program.getFunctionManager().getFunctionsOverlapping(body);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Function elem = iter.next();
			AddressSetView funcBody = elem.getBody();
			if (funcBody.contains(entry)) {
				bodyChangeMap.put(elem, funcBody);
				// re-define the function that does contain me....
				funcBody = funcBody.subtract(body);
				elem.setBody(funcBody);
			}
			else {
				// else, the body flowed into an existing function
				body = body.subtract(funcBody);
			}
		}
		return body;
	}

	/**
	 * Remove any existing functions bodies from the new functions body at entry.
	 *
	 * @param entry
	 * @param body
	 * @param monitor
	 * @return the new body, or null if body could not be created and need to abort function creation.
	 *
	 * @throws CancelledException
	 */
	private AddressSetView removeExistingFunctionsFromBody(Address entry, AddressSetView body,
			TaskMonitor monitor) throws CancelledException {
		Iterator<Function> iter = program.getFunctionManager().getFunctionsOverlapping(body);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Function elem = iter.next();
			if (elem.getEntryPoint().equals(entry)) {
				// if finding the entrypoint, need to redefine the functions body.
				if (!findEntryPoint) {
					long bodySize = elem.getBody().getNumAddresses();
					// if not finding the entry point, and bodysize > 1, bad function
					if (bodySize != 1) {
						return null;
					}
				}
			}
			else {
				AddressSetView bodyInConflict = elem.getBody();
				// catch functions that are place-holders for a function yet to be disassembled
				if (bodyInConflict.getNumAddresses() == 1) {
					bodyInConflict = getFunctionBody(program, elem.getEntryPoint(), false, monitor);
					if (bodyInConflict.contains(entry)) {
						continue;
					}
				}
				body = body.subtract(bodyInConflict);
			}
		}
		return body;
	}

	private boolean handleExistingFunction(TaskMonitor monitor, Address entry,
			Function existingFunction) throws OverlappingFunctionException, CancelledException {
		long bodySize = existingFunction.getBody().getNumAddresses();
		// if only a single byte function, it is most likely a place-holder function
		if (bodySize > 1) {
			if (!recreateFunction) {
				// Function at entry already exists and recreateFunction not enabled
				return false;
			}
			// if it is a thunk, then we're done
			if (resolveThunk(entry, null, monitor)) {
				return true;
			}
		}
		// function already exists, or size is one, must want to fixup the body.
		//    if re-creating the body, always return true even if the function body didn't change.
		if (fixupFunctionBody(program, existingFunction, monitor) || recreateFunction) {
			return true;
		}
		return false;
	}

	/**
	 * resolve thunks by checking for a thunk and creating the thunk if it is one
	 *
	 * @param entry function entry point to check for thunk
	 * @param body new function body
	 * @param monitor
	 * @return true if the entry resolved to a thunk
	 *
	 * @throws OverlappingFunctionException
	 */
	private boolean resolveThunk(Address entry, AddressSetView body, TaskMonitor monitor)
			throws OverlappingFunctionException {

		Address thunkedAddr = CreateThunkFunctionCmd.getThunkedExternalFunctionAddress(program, entry);
		if (thunkedAddr == null) {
			thunkedAddr = CreateThunkFunctionCmd.getThunkedAddr(program, entry);
		}
		if (thunkedAddr == null || thunkedAddr.equals(entry)) {
			return false;
		}
		if (referringThunkAddresses != null && referringThunkAddresses.contains(entry)) {
			throw new OverlappingFunctionException(
				"Invalid referenced function: circular thunk reference at " + entry);
		}
		// Handles simple check for single computed jump - may need to add more complex cases
		CreateThunkFunctionCmd cmd =
			new CreateThunkFunctionCmd(entry, body, thunkedAddr, referringThunkAddresses);
		if (cmd.applyTo(program, monitor)) {
			this.newFunc = cmd.getThunkFunction();
			return true;
		}
		return false;
	}

	/**
	 * using the body map revert any changes made to function bodies
	 *
	 * @param bodyChangeMap
	 */
	private void restoreOriginalBodies(Map<Function, AddressSetView> bodyChangeMap) {
		Set<Map.Entry<Function, AddressSetView>> entries = bodyChangeMap.entrySet();
		Iterator<Map.Entry<Function, AddressSetView>> iter = entries.iterator();
		while (iter.hasNext()) {
			Map.Entry<Function, AddressSetView> entry = iter.next();
			try {
				entry.getKey().setBody(entry.getValue());
			}
			catch (OverlappingFunctionException e) {
				// This shouldn't happen.
				e.printStackTrace();
			}
		}
	}

	/**
	 * Follow flow back from the address trying to find an existing function this fragment belongs to
	 *
	 * @param bodyAddr address that should be in the body of a function
	 * @return
	 */
	private Address findFunctionEntry(Address bodyAddr) {
		Address entry = bodyAddr;

		// if there is no function, then just follow some flow backwards
		AddressSet subSet = new AddressSet();
		Instruction followInstr = program.getListing().getInstructionContaining(entry);
		while (followInstr != null && !subSet.contains(followInstr.getMinAddress())) {
			subSet.addRange(followInstr.getMinAddress(), followInstr.getMaxAddress());

			// see if we have wandered backward into a function
			Function func =
				program.getFunctionManager().getFunctionContaining(followInstr.getMinAddress());
			if (func != null) {
				entry = func.getEntryPoint();
				break;
			}
			Address fallFrom = followInstr.getFallFrom();
			if (fallFrom == null) {
				ReferenceIterator iter = followInstr.getReferenceIteratorTo();
				if (!iter.hasNext()) {
					break;
				}
				Reference ref = iter.next();
				if (ref.getReferenceType().isCall()) {
					entry = fallFrom;
					break;
				}
				fallFrom = ref.getFromAddress();
			}
			followInstr = program.getListing().getInstructionContaining(fallFrom);
		}

		return entry;
	}

	/**
	 * Find the function body by following all flows other than a call from the
	 * entry point.
	 * @param program the program where the function is being created.
	 * @param entry entry point to start tracing flow
	 *
	 * @return AddressSetView address set representing the body of the function
	 */
	public static AddressSetView getFunctionBody(TaskMonitor monitor, Program program,
			Address entry) throws CancelledException {
		CodeBlock block = null;

		PartitionCodeSubModel model = new PartitionCodeSubModel(program);
		//				MultEntSubModel model = new MultEntSubModel(program);
		block = model.getCodeBlockAt(entry, monitor);

		if (block == null) {
			return getFunctionBody(program, entry);
		}
		return block;
	}

	/**
	 * Find the function body by following all flows other than a call from the
	 * entry point.
	 * @param program the program where the function is being created.
	 * @param entry entry point to start tracing flow
	 *
	 * @return AddressSetView address set representing the body of the function
	 */
	public static AddressSetView getFunctionBody(Program program, Address entry) {
		return getFunctionBody(program, entry, true, null);
	}

	public static AddressSetView getFunctionBody(Program program, Address entry,
			TaskMonitor monitor) {
		return getFunctionBody(program, entry, false, monitor);
	}

	public static AddressSetView getFunctionBody(Program program, Address entry,
			boolean includeOtherFunctions, TaskMonitor monitor) {

		Instruction instr = program.getListing().getInstructionAt(entry);
		if (instr == null) {
			// return single byte body
			return new AddressSet(entry, entry);
		}

		FlowType[] dontFollow = { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
			RefType.UNCONDITIONAL_CALL, RefType.INDIRECTION };
		AddressSet start = new AddressSet(entry, entry);
		FollowFlow flow = new FollowFlow(program, start, dontFollow, includeOtherFunctions);
		return flow.getFlowAddressSet(monitor);
	}

	/**
	 * Recompute function body.  An open transaction must already exist.
	 * @param program the program the function is in.
	 * @param start_inst instruction that is within the function to be fixed up.
	 * @param monitor task monitor
	 * @return true if successful, false if cancelled or unable to fixup function or
	 * no function found containing the start address of the indicated instruction
	 */
	public static boolean fixupFunctionBody(Program program, Instruction start_inst,
			TaskMonitor monitor) throws CancelledException {
		// have no instruction, so nothing to do, body is already good.
		if (start_inst == null) {
			return true;
		}
		Function func =
			program.getFunctionManager().getFunctionContaining(start_inst.getMinAddress());
		return fixupFunctionBody(program, func, monitor);
	}

	/**
	 * Recompute function body.  An open transaction must already exist.
	 * @param program the program the function is in.
	 * @param func the function to be fixed up.  A null function will return false.
	 * @param monitor task monitor
	 * @return true if successful, false if unable to fixup function or
	 * no function found containing the start address of the indicated instruction
	 * @throws CancelledException if the function fixup is cancelled.
	 */
	public static boolean fixupFunctionBody(Program program, Function func, TaskMonitor monitor)
			throws CancelledException {
		if (func == null || func.isExternal()) {
			return false;
		}
		Address entry = func.getEntryPoint();
		AddressSetView newBody = getFunctionBody(program, entry, false, monitor);

		// function could now be a thunk, since someone is calling this because of a potential body flow change
		if (!func.isThunk() && resolveThunk(program, entry, newBody, monitor)) {
			// function flow might have changed, and could now be a thunk, without the body changing.
			// don't worry about it below, because if there is an overlapping body, something strange
			// going on, and the function should still be a thunk
			return true;
		}

		if (newBody == null || newBody.isEmpty()) {
			// don't set a new body, if body returned is null, or empty
			return false;
		}

		// new body was equal to old body, nothing to do.
		if (func.getBody().equals(newBody)) {
			return false;
		}

		try {
			func.setBody(newBody); // trigger analysis
		}
		catch (OverlappingFunctionException e) {
			// subtract out any existing functions that overlap the body
			Iterator<Function> iter = program.getFunctionManager().getFunctionsOverlapping(newBody);

			while (iter.hasNext()) {
				monitor.checkCanceled();
				Function elem = iter.next();
				if (elem.getEntryPoint().equals(entry)) {
					// if finding the entrypoint, need to redefine the functions body.
					continue;
				}
				AddressSetView bodyInConflict = elem.getBody();
				// catch functions that are place-holders for a function yet to be disassembled
				if (bodyInConflict.getNumAddresses() == 1) {
					bodyInConflict = getFunctionBody(program, elem.getEntryPoint(), false, monitor);
					if (bodyInConflict.contains(entry)) {
						continue;
					}
				}
				newBody = newBody.subtract(bodyInConflict);
			}
			try {
				func.setBody(newBody); // trigger analysis
			}
			catch (OverlappingFunctionException exc) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check and create a thunk function at entry.
	 * Called due to a function body change, or a reference having been created
	 * so there is no body
	 *
	 * @param program function is in
	 * @param entry entry point of the function
	 * @param monitor to allow canceling
	 *
	 * @return true if a thunk was created.
	 */
	private static boolean resolveThunk(Program program, Address entry, AddressSetView body,
			TaskMonitor monitor) {

		Address thunkedAddr = CreateThunkFunctionCmd.getThunkedAddr(program, entry);
		if (thunkedAddr == null || thunkedAddr.equals(entry)) {
			return false;
		}

		// don't know the body of the thunk.
		CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(entry, body, thunkedAddr);
		if (cmd.applyTo(program, monitor)) {
			return true;
		}
		return false;
	}
}
