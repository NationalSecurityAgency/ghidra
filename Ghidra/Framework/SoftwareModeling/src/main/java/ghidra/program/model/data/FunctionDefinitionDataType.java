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
package ghidra.program.model.data;

import java.util.ArrayList;

import ghidra.docking.settings.Settings;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UniversalID;

/**
 * Definition of a function for things like function pointers.
 */
public class FunctionDefinitionDataType extends GenericDataType implements FunctionDefinition {

	private DataType returnType = DataType.DEFAULT;
	private ParameterDefinition[] params;
	private String comment;
	private boolean hasVarArgs;
	private GenericCallingConvention genericCallingConvention = GenericCallingConvention.unknown;

	public FunctionDefinitionDataType(String name) {
		this(CategoryPath.ROOT, name, null, null);
	}

	public FunctionDefinitionDataType(String name, DataTypeManager dtm) {
		this(CategoryPath.ROOT, name, null, dtm);
	}

	public FunctionDefinitionDataType(CategoryPath path, String name) {
		this(path, name, null, null);
	}

	public FunctionDefinitionDataType(CategoryPath path, String name, DataTypeManager dtm) {
		this(path, name, null, dtm);
	}

	public FunctionDefinitionDataType(FunctionSignature sig) {
		this(CategoryPath.ROOT, sig.getName(), sig, null);
	}

	public FunctionDefinitionDataType(FunctionSignature sig, DataTypeManager dtm) {
		this(CategoryPath.ROOT, sig.getName(), sig, dtm);
	}

	public FunctionDefinitionDataType(CategoryPath path, String name, FunctionSignature sig) {
		this(path, name, sig, null);
	}

	public FunctionDefinitionDataType(CategoryPath path, String name, FunctionSignature sig,
			DataTypeManager dtm) {
		super(path, name, dtm);
		init(sig);
	}

	public FunctionDefinitionDataType(CategoryPath path, String name, FunctionSignature sig,
			UniversalID universalID, SourceArchive sourceArchive, long lastChangeTime,
			long lastChangeTimeInSourceArchive, DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		init(sig);
	}

	/**
	 * Create a Function Definition based on a Function
	 * @param function the function to use to create a Function Signature.
	 * @param formalSignature if true only original formal types will be retained and 
	 * auto-params discarded (e.g., this, __return_storage_ptr__, etc.).  If false,
	 * the effective signature will be used where forced indirect and auto-params
	 * are reflected in the signature.  This option has no affect if the specified 
	 * function has custom storage enabled.
	 */
	public FunctionDefinitionDataType(Function function, boolean formalSignature) {
		super(CategoryPath.ROOT, function.getName(), function.getProgram().getDataTypeManager());
		//signatureSource = function.getSignatureSource();
		//name = function.getName();
		comment = function.getComment();
		returnType = function.getReturn().getFormalDataType();

		Parameter[] parameters = function.getParameters();

		ArrayList<ParameterDefinition> paramList = new ArrayList<ParameterDefinition>();
		for (Parameter parameter : parameters) {
			if (formalSignature && parameter.isAutoParameter()) {
				continue;
			}
			paramList.add(getParameterDefinition(parameter, formalSignature));
		}
		params = paramList.toArray(new ParameterDefinition[paramList.size()]);

		hasVarArgs = function.hasVarArgs();

		PrototypeModel prototypeModel = function.getCallingConvention();

		if (prototypeModel == null) {
			genericCallingConvention = GenericCallingConvention.unknown;
		}
		else {
			genericCallingConvention = prototypeModel.getGenericCallingConvention();
		}
	}

	private ParameterDefinition getParameterDefinition(Parameter param, boolean useFormalType) {
		return new ParameterDefinitionImpl(param.getName(),
			useFormalType ? param.getFormalDataType() : param.getDataType(), param.getComment(),
			param.getOrdinal());
	}

	private void init(FunctionSignature sig) {
		returnType = DataType.DEFAULT;
		params = new ParameterDefinition[0];
		if (sig != null) {
			copySignature(sig);
		}
	}

	private void copySignature(FunctionSignature sig) {
		comment = sig.getComment();
		DataType rtnType = sig.getReturnType();
		setReturnType(rtnType.clone(getDataTypeManager()));
		setArguments(sig.getArguments());
		hasVarArgs = sig.hasVarArgs();
		genericCallingConvention = sig.getGenericCallingConvention();
	}

	@Override
	public void setArguments(ParameterDefinition[] args) {
		params = new ParameterDefinition[args.length];
		for (int i = 0; i < args.length; i++) {
			DataType dt = args[i].getDataType();
			params[i] = new ParameterDefinitionImpl(args[i].getName(),
				dt.clone(getDataTypeManager()), args[i].getComment(), i);
		}
	}

	@Override
	public void setReturnType(DataType type) {
		returnType = ParameterDefinitionImpl.validateDataType(type, dataMgr, true);
	}

	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	@Override
	public void setVarArgs(boolean hasVarArgs) {
		this.hasVarArgs = hasVarArgs;
	}

	@Override
	public void setGenericCallingConvention(GenericCallingConvention genericCallingConvention) {
		this.genericCallingConvention = genericCallingConvention;
	}

	@Override
	public GenericCallingConvention getGenericCallingConvention() {
		return genericCallingConvention != null ? genericCallingConvention
				: GenericCallingConvention.unknown;
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return new FunctionDefinitionDataType(getCategoryPath(), getName(), this, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (getDataTypeManager() == dtm) {
			return this;
		}
		return new FunctionDefinitionDataType(getCategoryPath(), getName(), this, getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return getPrototypeString();
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public String getDescription() {
		return "Function:     " + getMnemonic(null);
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		return getPrototypeString();
	}

	@Override
	public String getPrototypeString() {
		return getPrototypeString(false);
	}

	@Override
	public String getPrototypeString(boolean includeCallingConvention) {
		StringBuffer buf = new StringBuffer();
		buf.append((returnType != null ? returnType.getDisplayName() : "void"));
		buf.append(" ");
		if (includeCallingConvention &&
			genericCallingConvention != GenericCallingConvention.unknown) {
			buf.append(genericCallingConvention.name());
			buf.append(" ");
		}
		buf.append(name);
		buf.append("(");
		int n = params.length;
		for (int i = 0; i < n; i++) {
			ParameterDefinition param = params[i];
			buf.append(param.getDataType().getDisplayName());
			buf.append(" ");
			buf.append(param.getName());
			if ((i < (n - 1)) || hasVarArgs) {
				buf.append(", ");
			}
		}
		if (hasVarArgs) {
			buf.append(VAR_ARGS_DISPLAY_STRING);
		}
		else if (params.length == 0) {
			buf.append(VOID_PARAM_DISPLAY_STRING);
		}
		buf.append(")");

		return buf.toString();
	}

	@Override
	public ParameterDefinition[] getArguments() {
		ParameterDefinition[] args = new ParameterDefinition[params.length];
		System.arraycopy(params, 0, args, 0, args.length);
		return args;
	}

	@Override
	public DataType getReturnType() {
		return returnType;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public boolean hasVarArgs() {
		return hasVarArgs;
	}

	/**
	 * Compare the comment of the given function signature to my comment.
	 * 
	 * @param sig signature to compare the comment
	 * 
	 * @return true if the comments match
	 */
	private boolean compareComment(FunctionSignature sig) {
		if (sig.getComment() == null && this.comment == null) {
			return true;
		}
		if (this.comment == null) {
			return false;
		}
		return (this.comment.equals(sig.getComment()));
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (!(dt instanceof FunctionDefinition)) {
			return false;
		}
		return isEquivalentSignature((FunctionDefinition) dt);
	}

	@Override
	public boolean isEquivalentSignature(FunctionSignature signature) {
		if (signature == this) {
			return true;
		}
		if ((signature.getName().equals(this.name)) && (compareComment(signature)) &&
			(DataTypeUtilities.isSameOrEquivalentDataType(signature.getReturnType(),
				this.returnType)) &&
			(hasVarArgs == signature.hasVarArgs()) &&
			(genericCallingConvention == signature.getGenericCallingConvention())) {
			ParameterDefinition[] args = signature.getArguments();
			if (args.length == this.params.length) {
				for (int i = 0; i < args.length; i++) {
					if (!args[i].isEquivalent(this.params[i])) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {

		if (newDt == this) {
			// avoid creating circular dependency
			newDt = DataType.DEFAULT;
		}
		DataType retType = getReturnType();
		if (oldDt == retType) {
			try {
				setReturnType(newDt);
			}
			catch (IllegalArgumentException e) {
				// oldDt replaced with incompatible type - treat as removal
				dataTypeDeleted(oldDt);
				return;
			}
		}
		for (ParameterDefinition param : params) {
			if (param.getDataType() == oldDt) {
				try {
					param.setDataType(newDt);
				}
				catch (IllegalArgumentException e) {
					// oldDt replaced with incompatible type - treat as removal
					dataTypeDeleted(oldDt);
					return;
				}
			}
		}
	}

	@Override
	public void replaceArgument(int ordinal, String newName, DataType dt, String newComment,
			SourceType source) {

		if (ordinal >= params.length) {
			ParameterDefinition[] newParams = new ParameterDefinition[ordinal + 1];
			System.arraycopy(params, 0, newParams, 0, params.length);
			for (int i = params.length; i < ordinal + 1; i++) {
				newParams[i] = new ParameterDefinitionImpl(Function.DEFAULT_PARAM_PREFIX + (i + 1),
					DataType.DEFAULT, newComment, i);
			}
			params = newParams;
		}
		params[ordinal] = new ParameterDefinitionImpl(newName, dt, newComment, ordinal);
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// ignore - no affect
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (returnType == dt) {
			returnType = DataType.DEFAULT;
		}
		for (ParameterDefinition param : params) {
			if (param.getDataType() == dt) {
				param.setDataType(DataType.DEFAULT);
			}
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignore - no affect
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public String toString() {
		return getPrototypeString(true);
	}

}
