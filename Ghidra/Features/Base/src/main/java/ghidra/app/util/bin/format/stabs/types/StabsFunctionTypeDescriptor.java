package ghidra.app.util.bin.format.stabs.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsUtils;
import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Function Type implementation of the StabTypeDescriptor
 */
public final class StabsFunctionTypeDescriptor extends AbstractStabsFunctionTypeDescriptor {

	private static final Pattern PATTERN = Pattern.compile(",(\\d+);");

	private final List<StabsTypeDescriptor> parameters;
	private final StabsTypeDescriptor returnType;
	private final FunctionDefinition dt;
	
	// initial size of 1
	private int length = 1;

	/**
	 * Constructs a new StabsFunctionTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor is invalid
	 */
	StabsFunctionTypeDescriptor(StabsSymbolDescriptor symbol, String stab)
		throws StabsParseException {
			super(symbol, stab);
			this.returnType = getTypeDescriptor(symbol, stab.substring(1));
			length += returnType.getLength();
			String subStab = stab.substring(length);
			FunctionDefinition def;
			if (symbol.getSymbolDescriptorType() == StabsSymbolDescriptorType.FUNCTION) {
				def = new FunctionDefinitionDataType(path, symbol.getName(), dtm);
			} else {
				def = (FunctionDefinition) file.getDefaultFunction(returnType.getDataType());
			}
			this.parameters = getParameters(subStab, def);
			this.dt = (FunctionDefinition) dtm.resolve(def, REPLACE_HANDLER);
	}

	private List<StabsTypeDescriptor> getParameters(String subStab, FunctionDefinition def)
		throws StabsParseException {
			Matcher matcher = PATTERN.matcher(subStab);
			List<StabsTypeDescriptor> descriptors;
			if (matcher.lookingAt()) {
				length = matcher.group().length();
				descriptors = new ArrayList<>(Integer.parseInt(matcher.group(1)));
				for (int i = 0; i < descriptors.size(); i++) {
					StabsTypeDescriptor type = new StabsParameterTypeDescriptor(this, subStab);
					descriptors.add(type);
					length += type.getLength();
				}
				return descriptors;
			} else {
				descriptors = Collections.emptyList();
			}
			if (StabsUtils.isGnu(program)) {
				if (descriptors.isEmpty() || !DataType.VOID.isEquivalent(
					descriptors.get(descriptors.size()-1).getDataType())) {
						def.setVarArgs(true);
					}
			}
			return descriptors;
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.FUNCTION;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public StabsTypeDescriptor getReturnType() {
		return returnType;
	}

	@Override
	public List<StabsTypeDescriptor> getParameters() throws StabsParseException {
		return parameters;
	}
}
