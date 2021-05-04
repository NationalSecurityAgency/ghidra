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
package ghidra.trace.database.symbol;

import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.Range;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.symbol.OverlappingNamespaceException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.program.DBTraceProgramView;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.exception.InvalidInputException;

public class DBTraceFunctionSymbolView
		extends AbstractDBTraceSymbolSingleTypeWithLocationView<DBTraceFunctionSymbol>
		implements TraceFunctionSymbolView {
	protected static final PrototypeModel[] EMPTY_MODEL_LIST = new PrototypeModel[] {};

	protected static void assertProperSpace(AddressSpace expected, AddressSetView body) {
		if (!expected.isMemorySpace()) {
			throw new IllegalArgumentException("Function must be in memory space");
		}
		for (AddressRange rng : body) {
			if (rng.getAddressSpace() != expected) {
				throw new IllegalArgumentException(
					"Function body must be in same space as entry point");
			}
		}
	}

	public DBTraceFunctionSymbolView(DBTraceSymbolManager manager) {
		super(manager, SymbolType.FUNCTION.getID(), manager.functionStore);
	}

	protected DBTraceNamespaceSymbol doValidateParentAndEntry(DBTraceNamespaceSymbol proposed,
			Address entryPoint) {
		if (proposed == null) {
			return manager.globalNamespace;
		}
		DBTraceProgramView program = manager.trace.getProgramView();
		if (!SymbolType.FUNCTION.isValidAddress(program, entryPoint)) {
			throw new IllegalArgumentException("Invalid function entry point: " + entryPoint);
		}
		if (!SymbolType.FUNCTION.isValidParent(program, proposed, entryPoint, false)) {
			throw new IllegalArgumentException("Invalid function namespace: " + proposed);
		}

		return proposed;
	}

	protected SourceType doValidateSource(SourceType proposed, String name, Address entryPoint) {
		if (!SymbolType.FUNCTION.isValidSourceType(proposed, entryPoint)) {
			throw new IllegalArgumentException("Invalid function source type: " + proposed);
		}
		return proposed;
	}

	protected String doValidateName(String proposed, Address entryPoint, SourceType source)
			throws InvalidInputException {
		if (source == SourceType.DEFAULT) {
			return "";
		}
		// TODO: Do entryPoint and source no longer matter? (see commit 898da2b)
		SymbolUtilities.validateName(proposed);
		return proposed;
	}

	protected void assertNotOverlapping(DBTraceFunctionSymbol exclude, Address entryPoint,
			Range<Long> span, AddressSetView proposedBody) throws OverlappingFunctionException {
		for (AddressRange rng : proposedBody) {
			for (DBTraceFunctionSymbol overlap : manager.functions.getIntersecting(span, null, rng,
				false, true)) {
				if (overlap != exclude) {
					throw new OverlappingFunctionException(entryPoint,
						new OverlappingNamespaceException(rng.getMinAddress(),
							rng.getMaxAddress()));
				}
			}
		}
	}

	@Override
	public DBTraceFunctionSymbol add(Range<Long> lifespan, Address entryPoint, AddressSetView body,
			String name, TraceFunctionSymbol thunked, TraceNamespaceSymbol parent,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		if (name == null || name.length() == 0 || SymbolUtilities.isReservedDynamicLabelName(name,
			manager.trace.getBaseAddressFactory())) {
			source = SourceType.DEFAULT;
			name = "";
		}
		else {
			DBTraceSymbolManager.assertValidName(name);
		}
		if (!"".equals(name) && source == SourceType.DEFAULT) {
			throw new IllegalArgumentException(
				"Cannot create DEFAULT function with non-default name");
		}
		if (!body.contains(entryPoint)) {
			throw new IllegalArgumentException("Function body must contain the entry point");
		}
		assertProperSpace(entryPoint.getAddressSpace(), body);
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceNamespaceSymbol dbnsParent =
				parent == null ? null : manager.assertIsMine((Namespace) parent);
			manager.assertValidThreadAddress(null, entryPoint);
			DBTraceFunctionSymbol dbThunked =
				thunked == null ? null : manager.assertIsMine((Function) thunked);

			if (manager.trace.getCodeManager()
					.definedData()
					.getAt(
						DBTraceUtils.lowerEndpoint(lifespan), entryPoint) != null) {
				throw new IllegalArgumentException(
					"Function entry point cannot be at defined data");
			}

			if (dbThunked != null && name.equals(dbThunked.getName())) {
				source = SourceType.DEFAULT;
				name = "";
			}

			assertNotOverlapping(null, entryPoint, lifespan, body);
			dbnsParent = doValidateParentAndEntry(dbnsParent, entryPoint);
			source = doValidateSource(source, name, entryPoint);
			name = doValidateName(name, entryPoint, source);

			DBTraceLabelSymbol toPromote = manager.labels.getChildWithNameAt(name,
				DBTraceUtils.lowerEndpoint(lifespan), null, entryPoint, dbnsParent);
			if (toPromote != null && toPromote.getLifespan().equals(lifespan)) {
				toPromote.delete();
			}

			DBTraceFunctionSymbol function = store.create();
			function.set(lifespan, entryPoint, name, dbThunked, dbnsParent, source);
			function.doCreateReturnParameter();
			for (AddressRange rng : body) {
				manager.putID(lifespan, null, rng, function.getID());
			}

			cacheForAt.notifyNewEntries(lifespan, body, function);

			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceSymbolChangeType.ADDED, null, function));
			return function;
		}
	}

	public static List<String> getCallingConventionNames(CompilerSpec cs) {
		PrototypeModel[] namedCCs = cs.getCallingConventions();
		List<String> names = new ArrayList<>(2 + namedCCs.length);
		names.add(Function.UNKNOWN_CALLING_CONVENTION_STRING);
		names.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
		for (PrototypeModel model : namedCCs) {
			names.add(model.getName());
		}
		return names;
	}

	@Override
	public List<String> getCallingConventionNames() {
		// TODO: Allow for user-selected compiler spec(s)
		return getCallingConventionNames(manager.trace.getBaseCompilerSpec());
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		CompilerSpec cs = manager.trace.getBaseCompilerSpec();
		if (cs == null) {
			return null;
		}
		return cs.getDefaultCallingConvention();
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		CompilerSpec cs = manager.trace.getBaseCompilerSpec();
		if (cs == null) {
			return null;
		}
		if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)) {
			return null;
		}
		if (Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name)) {
			return cs.getDefaultCallingConvention();
		}
		return cs.getCallingConvention(name);
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
		CompilerSpec cs = manager.trace.getBaseCompilerSpec();
		if (cs == null) {
			return EMPTY_MODEL_LIST;
		}
		return cs.getCallingConventions();
	}

	// TODO: Move this into a FunctionUtilities class?
	public static Variable getReferencedVariable(Function function, Address instrAddr,
			Address storageAddr, int size, boolean isRead, Language language) {
		Variable variables[] = function.getAllVariables();

		Parameter paramCandidate = null;
		List<Variable> localCandidates = null;
		Variable firstCandidate = null;

		size = Math.min(1, size);
		Register register = language.getRegister(storageAddr, size);

		for (Variable var : variables) {
			VariableStorage varStorage = var.getVariableStorage();

			// TODO: It seems this check will miss intersection if storageAddr precedes the
			// variable, but size is large enough to intersect.
			if ((register != null && varStorage.intersects(register)) ||
				(register == null && varStorage.contains(storageAddr))) {

				if (var instanceof Parameter) {
					paramCandidate = (Parameter) var;
				}
				else if (firstCandidate != null) {
					if (localCandidates == null) {
						localCandidates = new ArrayList<>();
						localCandidates.add(firstCandidate);
					}
					localCandidates.add(var);
				}
				else {
					firstCandidate = var;
				}
			}
		}

		int useOffset = (int) instrAddr.subtract(function.getEntryPoint());
		if (isRead) {
			if (useOffset == 0) {
				return paramCandidate;
			}
			--useOffset;
		}
		if (useOffset < 0) {
			// A bit of a hack to deal with negative offsets (from function entry)
			useOffset = Integer.MAX_VALUE - useOffset;
		}

		if (localCandidates == null) {
			if (firstCandidate != null) {
				int varFirstUse = firstCandidate.getFirstUseOffset();
				if (varFirstUse < 0) {
					varFirstUse = Integer.MAX_VALUE - varFirstUse;
				}
				if (varFirstUse <= useOffset) {
					return firstCandidate;
				}
			}
			return null;
		}

		Variable bestVar = null;
		int bestFirstUse = 0;
		for (Variable var : localCandidates) {
			int varFirstUse = var.getFirstUseOffset();
			if (varFirstUse < 0) {
				varFirstUse = Integer.MAX_VALUE - varFirstUse;
			}
			if (varFirstUse <= useOffset && (bestVar == null || bestFirstUse < varFirstUse)) {
				bestVar = var;
				bestFirstUse = varFirstUse;
			}
		}
		if (bestVar == null) {
			bestVar = paramCandidate;
		}
		return bestVar;
	}
}
