package ghidra.app.util.bin.format.stabs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;

/**
 * Function implementation of the StabSymbolDescriptor
 */
public final class StabsFunctionSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	public static final String CHILD_PATH = "functions";
	private static final String THIS_PARAM = "this";

	/** Potential Function Types */
	public static enum FunctionType {
		FILE,
		GLOBAL,
		NESTED,
		MODULE,
		STATIC
	}

	private final DataType dt;
	private final FunctionType type;
	private final List<StabsParameterSymbolDescriptor> parameters;
	private final StabsTypeDescriptor returnType;
	private final DemangledFunction demangled;
	private GenericCallingConvention cc = GenericCallingConvention.unknown;

	/**
	 * Constructs a new StabsFunctionSymbolDescriptor
	 * @param stabs the list of stabs containing this descriptor and the proceeding
	 * ones containing any potential parameters.
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one of its parameters is invalid
	 */
	StabsFunctionSymbolDescriptor(List<String> stabs, StabsFile file) throws StabsParseException {
		super(stabs.get(0), file);
		this.type = getType(descriptor);
		String typeString = stab.substring(name.length()+2);
		this.returnType = StabsTypeDescriptorFactory.getTypeDescriptor(this, typeString);
		this.demangled = doGetDemangled();
		this.parameters = parseParameters(stabs.subList(1, stabs.size()));
		this.dt = buildDataType();
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof StabsFunctionSymbolDescriptor) {
			StabsFunctionSymbolDescriptor other = (StabsFunctionSymbolDescriptor) o;
			if (other.returnType.getDataType() == null) {
				return false;
			}
			return other.name.equals(name) &&
				other.returnType.getDataType().isEquivalent(returnType.getDataType());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	private DemangledFunction doGetDemangled() {
		DemangledObject o = DemanglerUtil.demangle(file.getProgram(), name);
		if (o instanceof DemangledFunction) {
			return (DemangledFunction) o;
		}
		return null;
	}

	/**
	 * Gets the number of StabTokens consumed while parsing this token
	 * @return the number of consumed tokens
	 */
	int getTokenCount() {
		return parameters.size();
	}

	/**
	 * Gets an immutable list of the parameter tokens.
	 * @return the parameter tokens.
	 */
	public List<StabsParameterSymbolDescriptor> getParameterDescriptors() {
		return Collections.unmodifiableList(parameters);
	}

	private DataType buildDataType() {
		CategoryPath funPath = new CategoryPath(path, CHILD_PATH);
		FunctionDefinitionDataType funDt = new FunctionDefinitionDataType(funPath, name, dtm);
		funDt.setReturnType(returnType.getDataType());
		ParameterDefinition[] params = new ParameterDefinition[parameters.size()];
		for (int i = 0; i < parameters.size(); i++) {
			StabsParameterSymbolDescriptor token = parameters.get(i);
			params[i] = new ParameterDefinitionImpl(
				token.name, token.getDataType(), null);

		}
		funDt.setArguments(params);
		funDt.setGenericCallingConvention(cc);
		return dtm.resolve(funDt, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private FunctionType getType(char c) throws StabsParseException {
		switch (c) {
			case 'f':
				return FunctionType.FILE;
			case 'F':
				return FunctionType.GLOBAL;
			case 'I':
			case 'J':
				return FunctionType.NESTED;
			case 'm':
				return FunctionType.MODULE;
			case 'Q':
				return FunctionType.STATIC;
			default:
				throw new StabsParseException(name, stab);
		}
	}

	private List<StabsParameterSymbolDescriptor> parseParameters(List<String> stabs) throws StabsParseException {
		List<StabsParameterSymbolDescriptor> params = new LinkedList<>();
		for (String stab : stabs) {
			try {
				StabsSymbolDescriptorType type =
					StabsSymbolDescriptorType.getSymbolType(stab);
				if (type == StabsSymbolDescriptorType.PARAMETER) {
					StabsParameterSymbolDescriptor param =
						new StabsParameterSymbolDescriptor(stab, file);
					if (param.name.equals(THIS_PARAM)) {
						// set the calling convention to __thiscall and continue
						cc = GenericCallingConvention.thiscall;
						continue;
					}
					params.add(param);
				} else if (type == StabsSymbolDescriptorType.VARIABLE) {
					new StabsVariableSymbolDescriptor(stab, file);
				} else {
					break;
				}
			} catch (IllegalStateException e) {
				// no stab
			} catch (StabsParseException e) {
				// reached end of parameters
				break;
			}
		}
		return new ArrayList<>(params);
	}

	/**
	 * Gets the type of function being represented
	 * @return the function type
	 */
	public FunctionType getFunctionType() {
		return type;
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.FUNCTION;
	}

	/**
	 * Gets the demangled function if the name was mangled
	 * @return the demangled or null if the name wasn't mangled
	 */
	public DemangledFunction getDemangledFunction() {
		return demangled;
	}
	
}
