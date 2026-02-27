package ghidra.app.util.bin.format.stabs.types;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.program.model.data.DataType;

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

public final class StabsMethodTypeDescriptor extends AbstractStabsFunctionTypeDescriptor {

	private StabsTypeDescriptor returnType;
	private final List<StabsTypeDescriptor> parameters;
	private final DataType dt;

	StabsMethodTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		if (stab.charAt(1) == '#') {
			this.returnType = doGetReturnType();
			this.parameters = Collections.emptyList();
		} else {
			this.parameters = setupParameters();
		}
		this.dt = doGetDataType();
	}

	protected List<StabsTypeDescriptor> setupParameters() throws StabsParseException {
		List<StabsTypeDescriptor> typeParams = new LinkedList<>();
		String currentStab = stab;
		do {
			currentStab = currentStab.substring(1);
			StabsTypeDescriptor type = getTypeDescriptor(symbol, currentStab);
			typeParams.add(type);
			currentStab = currentStab.substring(type.getLength());
		} while (!currentStab.isBlank() && currentStab.charAt(0) == ',');
		if (!typeParams.isEmpty()) {
			// ditch the class type
			typeParams.remove(0);
			returnType = typeParams.remove(0);
		}
		return Collections.unmodifiableList(typeParams);
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.METHOD;
	}

	@Override
	public int getLength() {
		// Only found in classes. Not necessary to calculate.
		return 0;
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
