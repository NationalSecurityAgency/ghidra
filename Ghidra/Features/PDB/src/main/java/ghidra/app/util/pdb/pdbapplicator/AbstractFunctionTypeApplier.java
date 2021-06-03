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

import ghidra.app.util.DataTypeNamingUtil;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.CallingConvention;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for certain function types.
 */
public abstract class AbstractFunctionTypeApplier extends MsTypeApplier {

	private FunctionDefinitionDataType functionDefinition;

	private MsTypeApplier returnApplier;
	private ArgumentsListTypeApplier argsListApplier;
	private CallingConvention callingConvention;
	private boolean hasThisPointer;

	/**
	 * Constructor for the applicator that applies a "function" type, transforming it into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMsType} to processes
	 */
	public AbstractFunctionTypeApplier(PdbApplicator applicator, AbstractMsType msType) {
		super(applicator, msType);
//		String funcName = applicator.getNextAnonymousFunctionName();
		functionDefinition = new FunctionDefinitionDataType(
			applicator.getAnonymousFunctionsCategory(), "_func", applicator.getDataTypeManager());
		// Updating before trying to apply... if applyFunction fails, then this name will go
		// unused for the most part, but we also will not get a conflict on the name.
//		applicator.incrementNextAnonymousFunctionName();
		dataType = functionDefinition;
	}

	//==============================================================================================
	@Override
	void deferredApply() throws PdbException, CancelledException {
		if (isDeferred()) {
			applyInternal();
		}
	}

	//==============================================================================================
	/**
	 * Returns the function definition being created by this applier.
	 * @return the function definition.
	 */
	FunctionDefinitionDataType getFunctionDefinition() {
		return functionDefinition;
	}

	@Override
	DataType getCycleBreakType() {
		if (dataType != null) {
			return dataType;
		}
		return functionDefinition;
	}

	/**
	 * Returns the type applier of the return type
	 * @return the type applier
	 */
	MsTypeApplier getReturnTypeApplier() {
		return applicator.getTypeApplier(getReturnRecordNumber());
	}

	/**
	 * Returns the {@link ArgumentsListTypeApplier}
	 * @return the type applier
	 */
	ArgumentsListTypeApplier getArgsListApplier() {
		MsTypeApplier argsApplier = applicator.getTypeApplier(getArgListRecordNumber());
		if (argsApplier instanceof ArgumentsListTypeApplier) {
			return (ArgumentsListTypeApplier) applicator.getTypeApplier(getArgListRecordNumber());
		}
		return null;
	}

	/**
	 * Returns the {@link CallingConvention}
	 * @return the calling convention
	 */
	protected abstract CallingConvention getCallingConvention();

	/**
	 * Returns whether the function has a "this" pointer
	 * @return {@code true} if it has a "this" pointer 
	 */
	protected abstract boolean hasThisPointer();

	/**
	 * Returns the {@link RecordNumber} of the function return type
	 * @return the record number
	 */
	protected abstract RecordNumber getReturnRecordNumber();

	/**
	 * Returns the {@link RecordNumber} of the function arguments list
	 * @return the record number
	 */
	protected abstract RecordNumber getArgListRecordNumber();

	/**
	 * Returns if known to be a constructor.
	 * @return true if constructor.
	 */
	protected boolean isConstructor() {
		return false;
	}

	/**
	 * Method to create the {@link DataType} based upon the type indices of the calling
	 * convention, return type, and arguments list. 
	 * @param callingConventionParam Identification of the {@link AbstractMsType} record of the
	 * {@link CallingConvention}.
	 * @param hasThisPointerParam true if has a this pointer
	 * @return {@link DataType} created or null upon issue.
	 * @throws PdbException when unexpected function internals are found.
	 * @throws CancelledException Upon user cancellation
	 */
	protected DataType applyFunction(CallingConvention callingConventionParam,
			boolean hasThisPointerParam) throws PdbException, CancelledException {
//		String funcName = applicator.getCategoryUtils().getNextAnonymousFunctionName();
//		FunctionDefinitionDataType functionDefinition = new FunctionDefinitionDataType(
//			applicator.getCategoryUtils().getAnonymousFunctionsCategory(), funcName,
//			applicator.getDataTypeManager());

		this.callingConvention = callingConventionParam;
		this.hasThisPointer = hasThisPointerParam;
		returnApplier = getReturnTypeApplier();
		argsListApplier = getArgsListApplier();

		applyOrDeferForDependencies();
//		applyInternal();

		// 20190725 remove for second pass in applicator
//		// TODO: what handler should we really use?
//		DataType resolvedFunctionDefinition = applicator.resolve(functionDefinition);
//
//		if (resolvedFunctionDefinition == null) {
//			applicator.getLog().appendMsg("Function definition type not resolved for " + functionDefinition.getName());
//			return null;
//		}
//		if (!(resolvedFunctionDefinition instanceof FunctionDefinition)) {
//			// Error... can this happen?
//			// Remove what was just created?
//			applicator.getLog().appendMsg("Non-function resolved for " + functionDefinition.getName());
//			return null;
//		}

//		// Only update if successful.
//		applicator.getCategoryUtils().incrementNextAnonymousFunctionName();
//		return resolvedFunctionDefinition;
		return functionDefinition;
	}

	private void applyOrDeferForDependencies() throws CancelledException {
		if (returnApplier.isDeferred()) {
			applicator.addApplierDependency(this, returnApplier);
			setDeferred();
		}
		if (argsListApplier != null) {
			argsListApplier.checkForDependencies(this);
		}

		if (!isDeferred()) {
			applyInternal();
		}
	}

	private void applyInternal() throws CancelledException {
		if (isApplied()) {
			return;
		}
		if (!setReturnType()) {
			return;
		}
		if (argsListApplier != null) {
			argsListApplier.applyTo(this);
		}
		setCallingConvention(applicator, callingConvention, hasThisPointer);
		DataTypeNamingUtil.setMangledAnonymousFunctionName(functionDefinition, "_func");
		setApplied();

//		resolvedDataType = applicator.resolveHighUse(dataType);
//		if (resolvedDataType != null) {
//			resolved = true;
//		}
	}

	private boolean setReturnType() {

		if (isConstructor()) {
			return false;
		}

		DataType returnDataType = returnApplier.getDataType();
		if (returnDataType == null) {
			applicator.appendLogMsg("Return type is null in " + functionDefinition.getName());
			return false;
		}
		functionDefinition.setReturnType(returnDataType);
		return true;
	}

	private void setCallingConvention(PdbApplicator applicator, CallingConvention callingConvention,
			boolean hasThisPointer) {
		GenericCallingConvention convention;
		if (hasThisPointer) {
			convention = GenericCallingConvention.thiscall;
		}
		else {
			// Since we are a member function, we will always assume a _thiscall...
			// but how do we know it is not a atatic member function (no "this")?
			switch (callingConvention) {
				// TODO: figure all of these out. 
				case THISCALL: // "this" passed in register (we have not yet seen this)
					convention = GenericCallingConvention.thiscall; // Is this correct if in reg?
					break;
				case NEAR_C: // we have seen this one 
					convention = GenericCallingConvention.cdecl;
					break;
				case NEAR_VECTOR: // we have seen this one 
					convention = GenericCallingConvention.vectorcall;
					break;
				default:
//				applicator.getLog().appendMsg(
//					"TODO: calling convention not implemented for value " + callingConventionVal +
//						" in " + funcName);
					//convention = GenericCallingConvention.cdecl;
					convention = GenericCallingConvention.cdecl;
					break;
			}
		}
		functionDefinition.setGenericCallingConvention(convention);
	}

}
