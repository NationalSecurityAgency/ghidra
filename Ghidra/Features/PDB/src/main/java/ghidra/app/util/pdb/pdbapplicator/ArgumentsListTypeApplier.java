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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractArgumentsListMsType;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractArgumentsListMsType} types.
 */
public class ArgumentsListTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for the applicator that applies a arguments list.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractArgumentsListMsType} to processes.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public ArgumentsListTypeApplier(PdbApplicator applicator, AbstractArgumentsListMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
	}

	//==============================================================================================
	@Override
	void deferredApply() throws PdbException, CancelledException {
		// Do nothing... Just need dependency tie of each argument to function.
	}

	//==============================================================================================
	// TODO: would be nice if we did not have to implement this method.  Want the applyTo() below.
	@Override
	void apply() throws PdbException, CancelledException {
//		addMyDependenciesOnly();
//		// Silently do nothing.
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

//	private void addMyDependenciesOnly() throws CancelledException, PdbException {
//		AbstractArgumentsListMsType argsList = (AbstractArgumentsListMsType) msType;
//		List<AbstractTypeIndex> list = argsList.getArgTypeIndexList();
//		for (AbstractTypeIndex element : list) {
//			applicator.checkCanceled();
//			AbstractMsTypeApplier argApplier = applicator.getTypeApplier(element.get());
//
//			if (argApplier instanceof PrimitiveTypeApplier &&
//				((PrimitiveTypeApplier) argApplier).isNoType()) {
//				// Arguments list is empty. (There better not have been any arguments up until
//				//  now.)
//				break;
//			}
//
//			if (argApplier instanceof AbstractDeferrableMsTypeApplier &&
//				((AbstractDeferrableMsTypeApplier) argApplier).isDeferred()) {
//				applicator.addApplierDependency(this, argApplier);
//				setDeferred();
//			}
//		}
//	}
//
	void checkForDependencies(AbstractFunctionTypeApplier functionApplier)
			throws CancelledException {
		AbstractArgumentsListMsType argsList = (AbstractArgumentsListMsType) msType;
		List<RecordNumber> args = argsList.getArgRecordNumbers();
		for (RecordNumber arg : args) {
			applicator.checkCanceled();
			MsTypeApplier argApplier = applicator.getTypeApplier(arg);

			if (argApplier instanceof PrimitiveTypeApplier &&
				((PrimitiveTypeApplier) argApplier).isNoType()) {
				// Arguments list is empty. (There better not have been any arguments up until
				//  now.)
				break;
			}

//			if (argApplier instanceof AbstractDeferrableMsTypeApplier &&
//				((AbstractDeferrableMsTypeApplier) argApplier).isDeferred()) {
//				applicator.addApplierDependency(functionApplier, argApplier);
//				functionApplier.setDeferred();
//			}
			if (argApplier.isDeferred()) {
				applicator.addApplierDependency(functionApplier, argApplier);
				functionApplier.setDeferred();
			}
		}
	}

	/**
	 * Apply this to function ({@link AbstractFunctionTypeApplier}). 
	 * @param functionApplier the {@link AbstractFunctionTypeApplier} to which to apply the
	 * arguments.
	 * @throws CancelledException Upon user cancellation
	 */
	void applyTo(AbstractFunctionTypeApplier functionApplier) throws CancelledException {
		FunctionDefinitionDataType functionDefinition = functionApplier.getFunctionDefinition();

		AbstractArgumentsListMsType argsList = (AbstractArgumentsListMsType) msType;
		List<RecordNumber> args = argsList.getArgRecordNumbers();
		List<ParameterDefinition> parameterDefinitionList = new ArrayList<>();
		int parameterCount = 0;
		for (RecordNumber arg : args) {
			applicator.checkCanceled();
			MsTypeApplier argApplier = applicator.getTypeApplier(arg);

			if (argApplier instanceof PrimitiveTypeApplier &&
				((PrimitiveTypeApplier) argApplier).isNoType()) {
				// Arguments list is empty. (There better not have been any arguments up until
				//  now.)
				break;
			}

			DataType argDataType = argApplier.getDataType();
			if (argDataType == null) {
				applicator.appendLogMsg(
					"PDB Warning: No type conversion for " + argApplier.getMsType().toString() +
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
				}
			}
		}
		functionDefinition.setArguments(parameterDefinitionList.toArray(
			new ParameterDefinition[parameterDefinitionList.size()]));
	}

//	/**
//	 * Apply this to function ({@link AbstractFunctionTypeApplier}). 
//	 * @param functionApplier the {@link AbstractFunctionTypeApplier} to which to apply the
//	 * arguments.
//	 * @throws PdbException when unexpected function internals are found.
//	 * @throws CancelledException Upon user cancellation
//	 */
//	public void applyTo(AbstractFunctionTypeApplier functionApplier)
//			throws CancelledException, PdbException {
//		FunctionDefinitionDataType functionDefinition = functionApplier.getFunctionDefinition();
//
//		AbstractArgumentsListMsType argsList = (AbstractArgumentsListMsType) msType;
//		List<AbstractTypeIndex> list = argsList.getArgTypeIndexList();
//		List<ParameterDefinition> parameterDefinitionList = new ArrayList<>();
//		int parameterCount = 0;
//		for (AbstractTypeIndex element : list) {
//			applicator.getMonitor().checkCanceled();
//			AbstractMsTypeApplier argApplier = applicator.getTypeApplier(element.get());
//
//			if (argApplier instanceof PrimitiveTypeApplier &&
//				((PrimitiveTypeApplier) argApplier).isNoType()) {
//				// Arguments list is empty. (There better not have been any arguments up until
//				//  now.)
//				break;
//			}
//
//			if (argApplier instanceof AbstractDeferrableMsTypeApplier &&
//				((AbstractDeferrableMsTypeApplier) argApplier).isDeferred()) {
//				applicator.addApplierDependency(functionApplier, argApplier);
//				functionApplier.setDeferred();
//			}
//
////			applicator.addApplierDependency(functionApplier, argApplier);
//			DataType argDataType = argApplier.getDataType();
//			if (argDataType == null) {
//				String message =
//					"PDB Warning: No type conversion for " + argApplier.getMsType().toString() +
//						" for parameter " + parameterCount + " of " + functionDefinition.getName();
//				applicator.getLog().appendMsg(message);
//			}
//			else {
//				ParameterDefinition parameterDefinition =
//					new ParameterDefinitionImpl(null, argDataType, "");
//				parameterDefinitionList.add(parameterDefinition);
//				parameterCount++;
//			}
//		}
//		functionDefinition.setArguments(parameterDefinitionList.toArray(
//			new ParameterDefinition[parameterDefinitionList.size()]));
//	}
//	
}
