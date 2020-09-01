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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.pdb.PdbNamespaceUtils;
import ghidra.program.model.data.DataType;

public abstract class AbstractComplexTypeApplier extends AbstractMsTypeApplier {

	protected SymbolPath symbolPath;
	protected SymbolPath fixedSymbolPath;

	protected AbstractComplexTypeApplier definitionApplier = null;
	protected AbstractComplexTypeApplier fwdRefApplier = null;

	public static AbstractComplexTypeApplier getComplexApplier(PdbApplicator applicator,
			RecordNumber recordNumber) throws PdbException {
		return (AbstractComplexTypeApplier) applicator.getApplierSpec(recordNumber,
			AbstractComplexTypeApplier.class);
	}

	/**
	 * Constructor for complex type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractEnumMsType} to process.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public AbstractComplexTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
		String fullPathName = msType.getName();
		symbolPath = new SymbolPath(SymbolPathParser.parse(fullPathName));
	}

	public SymbolPath getSymbolPath() {
		return symbolPath;
	}

	public boolean isForwardReference() {
		return ((AbstractComplexMsType) msType).getMsProperty().isForwardReference();
	}

	public boolean isFinal() {
		return ((AbstractComplexMsType) msType).getMsProperty().isSealed();
	}

	public void setFwdRefApplier(AbstractComplexTypeApplier fwdRefApplier) {
		this.fwdRefApplier = fwdRefApplier;
	}

	<T extends AbstractComplexTypeApplier> T getFwdRefApplier(Class<T> typeClass) {
		if (!typeClass.isInstance(fwdRefApplier)) {
			return null;
		}
		return typeClass.cast(fwdRefApplier);
	}

	public void setDefinitionApplier(AbstractComplexTypeApplier definitionApplier) {
		this.definitionApplier = definitionApplier;
	}

	<T extends AbstractComplexTypeApplier> T getDefinitionApplier(Class<T> typeClass) {
		if (!typeClass.isInstance(definitionApplier)) {
			return null;
		}
		return typeClass.cast(definitionApplier);
	}

	protected SymbolPath getFixedSymbolPath() { //return mine or my def's (and set mine)
		if (fixedSymbolPath != null) {
			return fixedSymbolPath;
		}

		if (definitionApplier != null && definitionApplier.getFixedSymbolPath() != null) {
			fixedSymbolPath = definitionApplier.getFixedSymbolPath();
			return fixedSymbolPath;
		}

		SymbolPath fixed = PdbNamespaceUtils.getFixUpSymbolPathNameOnly(symbolPath, index);
		if (symbolPath.equals(fixed)) {
			fixedSymbolPath = symbolPath;
		}
		else {
			fixedSymbolPath = fixed;
		}
		return fixedSymbolPath;
	}

	DataType getDataTypeInternal() {
		return dataType;
	}

}
