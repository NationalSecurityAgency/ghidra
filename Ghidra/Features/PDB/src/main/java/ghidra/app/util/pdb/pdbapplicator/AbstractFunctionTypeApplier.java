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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.DataTypeNamingUtil;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * Applier for certain function types.
 */
public abstract class AbstractFunctionTypeApplier extends MsTypeApplier {

	// Intended for: see children
	/**
	 * Constructor for the applicator that applies a "function" type, transforming it into a
	 * Ghidra DataType.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public AbstractFunctionTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	/**
	 * Returns the {@link CallingConvention}
	 * @param type the PDB type being inspected
	 * @return the calling convention
	 */
	protected abstract CallingConvention getCallingConvention(AbstractMsType type);

	/**
	 * Returns the function "this" pointer
	 * @param type the PDB type being inspected
	 * @param fixupContext the fixup context to use; or pass in null during fixup process
	 * @param breakCycle specify {@code true} when employing break-cycle logic (pointers to
	 * Composites within composites)
	 * @return the "this" pointer or null if does not have or is not a recognized type
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 */
	protected abstract Pointer getThisPointer(AbstractMsType type, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException;

	/**
	 * Returns the containing class if function member of class
	 * @param type the PDB type being inspected
	 * @param fixupContext the fixup context to use; or pass in null during fixup process
	 * @param breakCycle specify {@code true} when employing break-cycle logic (pointers to
	 * Composites within composites)
	 * @return the containing class composite type
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 */
	protected abstract Composite getContainingComplexApplier(AbstractMsType type,
			FixupContext fixupContext, boolean breakCycle) throws CancelledException, PdbException;

	/**
	 * Processes containing class if one exists
	 * @param type the PDB type being inspected
	 */
	protected abstract void processContainingType(AbstractMsType type);

	/**
	 * Returns if known to be a constructor.
	 * @param type the PDB type being inspected
	 * @return true if constructor.
	 */
	protected boolean isConstructor(AbstractMsType type) {
		return false;
	}

	/**
	 * Returns the {@link RecordNumber} of the function return type
	 * @param type the PDB type being inspected
	 * @return the record number
	 */
	protected abstract RecordNumber getReturnRecordNumber(AbstractMsType type);

	/**
	 * Returns the {@link RecordNumber} of the function arguments list
	 * @param type the PDB type being inspected
	 * @return the record number
	 */
	protected abstract RecordNumber getArgListRecordNumber(AbstractMsType type);

	private boolean setReturnType(FunctionDefinitionDataType functionDefinition,
			AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		if (isConstructor(type)) {
			return true;
		}
		RecordNumber returnRecord = getReturnRecordNumber(type);
		if (returnRecord == null) {
			return false;
		}
		DataType returnType =
			applicator.getProcessedDataType(returnRecord, fixupContext, breakCycle);
		if (returnType == null) {
			return false;
		}
		if (applicator.isPlaceholderPointer(returnType)) {
			return false;
		}
		functionDefinition.setReturnType(returnType);
		return true;
	}

	private void setCallingConvention(FunctionDefinitionDataType functionDefinition,
			CallingConvention callingConvention, Pointer thisPointer) {
		String convention;
		if (thisPointer != null) {
			convention = CompilerSpec.CALLING_CONVENTION_thiscall;
		}
		else {
			// Since we are a member function, we will always assume a _thiscall...
			// but how do we know it is not a static member function (no "this")?
			switch (callingConvention) {
				// TODO: figure all of these out.
				case THISCALL: // "this" passed in register (we have not yet seen this)
					convention = CompilerSpec.CALLING_CONVENTION_thiscall; // Is this correct if in reg?
					break;
				case NEAR_C: // we have seen this one 
					convention = CompilerSpec.CALLING_CONVENTION_cdecl;
					break;
				case NEAR_VECTOR: // we have seen this one 
					convention = CompilerSpec.CALLING_CONVENTION_vectorcall;
					break;
				default:
					convention = CompilerSpec.CALLING_CONVENTION_cdecl;
					break;
			}
		}
		try {
			functionDefinition.setCallingConvention(convention);
		}
		catch (InvalidInputException e) {
			applicator.appendLogMsg("Failed to set calling convention `" + convention + "` for " +
				functionDefinition.getName());
		}
	}

	private boolean setArguments(FunctionDefinitionDataType functionDefinition, AbstractMsType type,
			FixupContext fixupContext, boolean breakCycle) throws CancelledException, PdbException {

		RecordNumber argsRecord = getArgListRecordNumber(type);
		AbstractMsType aType = applicator.getPdb().getTypeRecord(argsRecord);
		if (!(aType instanceof AbstractArgumentsListMsType argsList)) {
			applicator.appendLogMsg(
				"PDB Warning: expecting args list but found " + aType.getClass().getSimpleName() +
					" for parameter list of " + functionDefinition.getName());
			return false;
		}

		boolean hasPlaceholder = false;

		List<RecordNumber> args = argsList.getArgRecordNumbers();
		List<ParameterDefinition> parameterDefinitionList = new ArrayList<>();
		int parameterCount = 0;
		for (RecordNumber arg : args) {
			applicator.checkCancelled();

			AbstractMsType argMsType = applicator.getPdb().getTypeRecord(arg);
			if (argMsType instanceof PrimitiveMsType primitive && primitive.isNoType()) {
				// Arguments list is empty. (There better not have been any arguments up until
				//  now.)
				break;
			}

			DataType argDataType = applicator.getProcessedDataType(arg, fixupContext, breakCycle);
			if (argDataType == null) {
				applicator.appendLogMsg(
					"PDB Warning: No type conversion for " + argMsType.toString() +
						" for parameter " + parameterCount + " of " + functionDefinition.getName());
			}
			else {
				if (applicator.isPlaceholderPointer(argDataType)) {
					hasPlaceholder = true;
				}
				try {
					ParameterDefinition parameterDefinition =
						new ParameterDefinitionImpl(null, argDataType, "");
					parameterDefinitionList.add(parameterDefinition);
					parameterCount++;
				}
				catch (IllegalArgumentException e) {
					try {
						DataType substitute =
							Undefined.getUndefinedDataType(argDataType.getLength());
						ParameterDefinition parameterDefinition =
							new ParameterDefinitionImpl(null, substitute, "");
						parameterDefinitionList.add(parameterDefinition);
						parameterCount++;
						applicator.appendLogMsg("PDB Warning: Could not apply type " + argDataType +
							" for parameter " + parameterCount + " of " +
							functionDefinition.getName() + ". Using undefined type instead.");
					}
					catch (IllegalArgumentException e1) {
						applicator.appendLogMsg("PDB Warning: Could not apply type " + argDataType +
							" for parameter " + parameterCount + " of " +
							functionDefinition.getName() + ". Undefined failed: " + e1);

					}
					return false;
				}
			}
		}
		if (hasPlaceholder) {
			return false;
		}
		functionDefinition.setArguments(parameterDefinitionList
				.toArray(new ParameterDefinition[parameterDefinitionList.size()]));
		return true;
	}

	@Override
	public DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		DataType existing = applicator.getDataType(type);
		if (existing != null) {
			return existing;
		}
		FunctionDefinitionDataType functionDefinition = new FunctionDefinitionDataType(
			applicator.getAnonymousFunctionsCategory(), "_func", applicator.getDataTypeManager());

		boolean hasPlaceholder = false;

		processContainingType(type);

		if (!setReturnType(functionDefinition, type, fixupContext, breakCycle)) {
			hasPlaceholder = true;
		}

		if (!setArguments(functionDefinition, type, fixupContext, breakCycle)) {
			hasPlaceholder = true;
		}

		if (hasPlaceholder) {
			return null;
		}

		Pointer thisPointer = getThisPointer(type, fixupContext, breakCycle);
		CallingConvention convention = getCallingConvention(type);
		setCallingConvention(functionDefinition, convention, thisPointer);

		DataTypeNamingUtil.setMangledAnonymousFunctionName(functionDefinition);

		DataType resolvedType = applicator.resolve(functionDefinition);
		applicator.putDataType(type, resolvedType);
		return resolvedType;
	}

}
