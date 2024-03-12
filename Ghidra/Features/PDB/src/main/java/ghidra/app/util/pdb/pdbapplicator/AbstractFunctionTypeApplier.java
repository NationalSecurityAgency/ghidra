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
public abstract class AbstractFunctionTypeApplier extends MsDataTypeApplier {

	// Intended for: see children
	/**
	 * Constructor for the applicator that applies a "function" type, transforming it into a
	 * Ghidra DataType
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
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
	 * Composites within composites)
	 * @return the "this" pointer or null if does not have or is not a recognized type
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 */
	protected abstract Pointer getThisPointer(AbstractMsType type)
			throws CancelledException, PdbException;

	/**
	 * Returns the RecordNumber of the function "this" pointer; {@code null} if not this pointer
	 * @param type the PDB type being inspected
	 * @return the record number of the "this" pointer or null if does not have or is not a
	 *  recognized type
	 */
	protected abstract RecordNumber getThisPointerRecordNumber(AbstractMsType type);

	/**
	 * Returns the RecordNumber of the containing class if function member of class; {@code null}
	 *  if no containing class
	 * @param type the PDB type being inspected
	 * @return the record number of the containing class composite type or {@code null} if none
	 */
	protected abstract RecordNumber getContainingComplexRecordNumber(AbstractMsType type);

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
			AbstractMsType type) {
		if (isConstructor(type)) {
			return true;
		}
		RecordNumber returnRecord = getReturnRecordNumber(type);
		DataType returnType = applicator.getDataType(returnRecord);
		if (returnType == null) {
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

	private boolean setArguments(FunctionDefinitionDataType functionDefinition, AbstractMsType type)
			throws CancelledException, PdbException {

		List<RecordNumber> args = getArgsRecordNumbers(type);

		List<ParameterDefinition> parameterDefinitionList = new ArrayList<>();
		int parameterCount = 0;
		for (RecordNumber arg : args) {
			applicator.checkCancelled();

			AbstractMsType argMsType = applicator.getTypeRecord(arg);
			if (argMsType instanceof PrimitiveMsType primitive && primitive.isNoType()) {
				// Arguments list is empty. (There better not have been any arguments up until
				//  now.)
				break;
			}

			DataType argDataType = applicator.getDataType(arg);
			if (argDataType == null) {
				applicator.appendLogMsg(
					"PDB Warning: No type conversion for " + argMsType.toString() +
						" for parameter " + parameterCount + " of " + functionDefinition.getName());
			}
			else {
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
		functionDefinition.setArguments(parameterDefinitionList
				.toArray(new ParameterDefinition[parameterDefinitionList.size()]));
		return true;
	}

	@Override
	boolean apply(AbstractMsType type)
			throws CancelledException, PdbException {

		if (!precheckOrScheduleDependencies(type)) {
			return false;
		}

		FunctionDefinitionDataType functionDefinition = new FunctionDefinitionDataType(
			applicator.getAnonymousFunctionsCategory(), "_func", applicator.getDataTypeManager());

		processContainingType(type);
		setReturnType(functionDefinition, type);
		setArguments(functionDefinition, type);
		Pointer thisPointer = getThisPointer(type);

		CallingConvention convention = getCallingConvention(type);
		setCallingConvention(functionDefinition, convention, thisPointer);

		DataTypeNamingUtil.setMangledAnonymousFunctionName(functionDefinition);
		DataType dataType = functionDefinition;

		applicator.putDataType(type, dataType);
		return true;
	}

	/**
	 * Uses {@link DefaultPdbApplicator#getDataTypeOrSchedule(RecordNumber)}) on all underlying
	 *  types to ensure that the types get scheduled... and detects whether any types were not yet
	 *  available so that this composite type is denoted as not done.
	 * @param type the MS type of the function
	 * @return {@code true} if all underlying types are already available
	 * @throws PdbException upon processing issue
	 */
	private boolean precheckOrScheduleDependencies(AbstractMsType type)
			throws PdbException {
		boolean done = true;

		RecordNumber returnRecordNumber = getReturnRecordNumber(type);
		DataType dt = applicator.getDataTypeOrSchedule(returnRecordNumber);
		if (dt == null) {
			done = false;
		}

		List<RecordNumber> args = getArgsRecordNumbers(type);
		for (RecordNumber argRecordNumber : args) {
			dt = applicator.getDataTypeOrSchedule(argRecordNumber);
			if (dt == null) {
				done = false;
			}
		}

		RecordNumber thisRecordNumber = getThisPointerRecordNumber(type);
		if (thisRecordNumber != null) {
			dt = applicator.getDataTypeOrSchedule(thisRecordNumber);
			if (dt == null) {
				done = false;
			}
		}

		RecordNumber containerRecordNumber = getContainingComplexRecordNumber(type);
		if (containerRecordNumber != null) {
			dt = applicator.getDataTypeOrSchedule(containerRecordNumber);
			if (dt == null) {
				done = false;
			}
		}

		return done;
	}

	private List<RecordNumber> getArgsRecordNumbers(AbstractMsType type) throws PdbException {
		RecordNumber argsRecord = getArgListRecordNumber(type);
		AbstractMsType aType = applicator.getTypeRecord(argsRecord);
		if (!(aType instanceof AbstractArgumentsListMsType argsList)) {
			throw new PdbException(
				"Expecting arguments list but got: " + aType.getClass().getSimpleName());
		}
		return argsList.getArgRecordNumbers();
	}

}
