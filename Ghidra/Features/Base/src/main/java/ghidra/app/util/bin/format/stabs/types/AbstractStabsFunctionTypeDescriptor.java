package ghidra.app.util.bin.format.stabs.types;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.app.util.bin.format.stabs.StabsUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER;
import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

abstract class AbstractStabsFunctionTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static final CategoryPath DEFAULT_PATH = new CategoryPath("/stabs/functions");

	private static final Pattern PATTERN =
		Pattern.compile(String.format("(?:(?:f)|(?:#+))(%s)", StabsTypeNumber.TYPE_NUMBER_PATTERN));

	protected AbstractStabsFunctionTypeDescriptor(StabsSymbolDescriptor symbol, String stab) {
		super(symbol, stab);
		if (this.path.isRoot()) {
			this.path = DEFAULT_PATH;
		}
	}

	/**
	 * Gets the return type descriptor
	 * @return the return type descriptor
	 */
	public abstract StabsTypeDescriptor getReturnType();

	/**
	 * Gets the parameter type descriptors
	 * @return the list of parameter type descriptors
	 * @throws StabsParseException if an error occurs parsing the parameters
	 */
	public abstract List<StabsTypeDescriptor> getParameters() throws StabsParseException;

	protected final StabsTypeDescriptor doGetReturnType() throws StabsParseException {
		Matcher matcher = PATTERN.matcher(stab);
		if (matcher.lookingAt()) {
			return getTypeDescriptor(symbol, stab.substring(matcher.start(1)));
		}
		return null;
	}

	private static ParameterDefinitionImpl convertParameter(StabsTypeDescriptor type) {
		try {
			return new ParameterDefinitionImpl(null, type.getDataType(), null);
		} catch (IllegalArgumentException e) {
			// this cannot occur. If it does then self destruct or something
			throw new RuntimeException(e);
		}
	}

	// necessary side affect of removing unnecessary final void parameter
	private boolean fixupVarargs(List<StabsTypeDescriptor> parameters) {
		if (StabsUtils.isGnu(program)) {
			if (!parameters.isEmpty()) {
				StabsTypeDescriptor type = parameters.get(parameters.size()-1);
				if (!type.getDataType().isEquivalent(DataType.VOID)) {
					return true;
				}
				parameters.remove(type);
			}
			return true;
		}
		return false;
	}

	protected final DataType doGetDataType() throws StabsParseException {
		FunctionDefinition def = new FunctionDefinitionDataType(path, symbol.getName(), dtm);
		List<StabsTypeDescriptor> parameters = new ArrayList<>(getParameters());
		fixupVarargs(parameters);
		ParameterDefinitionImpl[] params =
			parameters.stream()
					  .map(AbstractStabsFunctionTypeDescriptor::convertParameter)
					  .toArray(ParameterDefinitionImpl[]::new);
		def.setArguments(params);
		def.setReturnType(getReturnType().getDataType());
		return dtm.resolve(def, REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
	}	
}
