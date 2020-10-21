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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType;
import ghidra.app.util.pdb.PdbNamespaceUtils;
import ghidra.program.model.data.DataType;

/**
 * Applier for {@link AbstractComplexMsType} types.
 */
public abstract class AbstractComplexTypeApplier extends MsTypeApplier {

	protected SymbolPath symbolPath;
	protected SymbolPath fixedSymbolPath;

	protected AbstractComplexTypeApplier definitionApplier = null;
	protected AbstractComplexTypeApplier forwardReferenceApplier = null;

	public static AbstractComplexTypeApplier getComplexApplier(PdbApplicator applicator,
			RecordNumber recordNumber) throws PdbException {
		return (AbstractComplexTypeApplier) applicator.getApplierSpec(recordNumber,
			AbstractComplexTypeApplier.class);
	}

	/**
	 * Constructor for complex type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractComplexMsType} to process.
	 */
	public AbstractComplexTypeApplier(PdbApplicator applicator, AbstractComplexMsType msType) {
		super(applicator, msType);
		String fullPathName = msType.getName();
		symbolPath = new SymbolPath(SymbolPathParser.parse(fullPathName));
	}

	SymbolPath getSymbolPath() {
		return symbolPath;
	}

	boolean isForwardReference() {
		return ((AbstractComplexMsType) msType).getMsProperty().isForwardReference();
	}

	boolean isNested() {
		return ((AbstractComplexMsType) msType).getMsProperty().isNestedClass();
	}

	boolean isFinal() {
		return ((AbstractComplexMsType) msType).getMsProperty().isSealed();
	}

	void setForwardReferenceApplier(AbstractComplexTypeApplier forwardReferenceApplier) {
		this.forwardReferenceApplier = forwardReferenceApplier;
	}

	void setDefinitionApplier(AbstractComplexTypeApplier definitionApplier) {
		this.definitionApplier = definitionApplier;
	}

	<T extends AbstractComplexTypeApplier> T getDefinitionApplier(Class<T> typeClass) {
		if (!typeClass.isInstance(definitionApplier)) {
			return null;
		}
		return typeClass.cast(definitionApplier);
	}

	protected AbstractComplexTypeApplier getAlternativeTypeApplier() {
		if (isForwardReference()) {
			return definitionApplier;
		}
		return forwardReferenceApplier;
	}

	protected SymbolPath getFixedSymbolPath() { //return mine or my def's (and set mine)
		if (fixedSymbolPath != null) {
			return fixedSymbolPath;
		}

		if (definitionApplier != null && definitionApplier.getFixedSymbolPath() != null) {
			fixedSymbolPath = definitionApplier.getFixedSymbolPath();
			return fixedSymbolPath;
		}

		SymbolPath fixed = PdbNamespaceUtils.convertToGhidraPathName(symbolPath, index);
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
