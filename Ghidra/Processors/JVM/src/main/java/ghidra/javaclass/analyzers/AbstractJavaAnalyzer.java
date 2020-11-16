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
package ghidra.javaclass.analyzers;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractJavaAnalyzer implements Analyzer {

	@Override
	final public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		try {
			return analyze(program, set, monitor, log);
		}
		catch (Exception e) {
			log.appendException(e);
			e.printStackTrace();
		}
		return false;
	}

	@Override
	final public void analysisEnded(Program program) {
	}

	@Override
	final public void registerOptions(Options options, Program program) {
	}

	@Override
	final public void optionsChanged(Options propertyList, Program program) {
	}

	@Override
	final public boolean removed(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		return false;
	}

	final public void restoreDefaultOptions(Options propertyList, Program program) {
	}

	@Override
	final public boolean supportsOneTimeAnalysis() {
		return false;
	}

	public abstract boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws Exception;

	protected void changeDataSettings(Program program, TaskMonitor monitor) {
		monitor.setMessage("Changing data settings...");
		Address address = program.getMinAddress();
		while (!monitor.isCancelled()) {
			Data data = getDataAt(program, address);
			if (data == null) {
				data = getDataAfter(program, address);
			}
			if (data == null) {
				break;
			}
			int numComponents = data.getNumComponents();
			for (int i = 0; i < numComponents; ++i) {
				if (monitor.isCancelled()) {
					break;
				}
				Data component = data.getComponent(i);

				byte[] bytes = new byte[component.getLength()];
				try {
					program.getMemory().getBytes(component.getAddress(), bytes);
				}
				catch (MemoryAccessException e) {
				}

				boolean isAscii = true;
				for (byte b : bytes) {
					if (b < ' ' || b > '~') {
						isAscii = false;
					}
				}
				if (isAscii && bytes.length > 1) {
					changeFormatToString(component);
				}
				/*
				 * if (component.getFieldName().equals("magic") ||
				 * component.getFieldName().equals("identifier") ||
				 * component.getFieldName().equals("compression") ||
				 * component.getFieldName().equals("format") ||
				 * component.getFieldName().equals("type")) {
				 * changeFormatToString(component); }
				 */
			}
			address = address.add(data.getLength());
		}
	}

	protected void removeEmptyFragments(Program program) throws NotEmptyException {
		ProgramModule rootModule = program.getListing().getRootModule("Program Tree");
		Group[] children = rootModule.getChildren();
		for (Group child : children) {
			if (child instanceof ProgramFragment) {
				ProgramFragment fragment = (ProgramFragment) child;
				if (fragment.isEmpty()) {
					rootModule.removeChild(fragment.getName());
				}
			}
		}
	}

	protected void changeFormatToString(Data data) {
		SettingsImpl settings = new SettingsImpl(data);
		settings.setDefaultSettings(settings);
		SettingsDefinition[] settingsDefinitions = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition settingsDefinition : settingsDefinitions) {
			if (settingsDefinition instanceof FormatSettingsDefinition) {
				FormatSettingsDefinition format = (FormatSettingsDefinition) settingsDefinition;
				format.setChoice(data, FormatSettingsDefinition.CHAR);
			}
		}
	}

	protected ProgramFragment createFragment(Program program, String fragmentName, Address start,
			Address end) throws Exception {
		ProgramModule module = program.getListing().getDefaultRootModule();
		ProgramFragment fragment = getFragment(module, fragmentName);
		if (fragment == null) {
			fragment = module.createFragment(fragmentName);
		}
		fragment.move(start, end.subtract(1));
		return fragment;
	}

	protected ProgramFragment getFragment(ProgramModule module, String fragmentName) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group.getName().equals(fragmentName)) {
				return (ProgramFragment) group;
			}
		}
		return null;
	}

	protected Data getDataAt(Program program, Address address) {
		return program.getListing().getDefinedDataAt(address);
	}

	protected Data getDataAfter(Program program, Data data) {
		return getDataAfter(program, data.getMaxAddress());
	}

	protected Data getDataAfter(Program program, Address address) {
		return program.getListing().getDefinedDataAfter(address);
	}

	protected Address toAddr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected Address toCpAddr(Program program, long offset) {
		return program.getAddressFactory().getAddressSpace("constantPool").getAddress(offset);
	}

	protected Data createData(Program program, Address address, DataType datatype)
			throws Exception {
		if (datatype instanceof StringDataType) {
			CreateStringCmd cmd = new CreateStringCmd(address);
			if (!cmd.applyTo(program)) {
				throw new RuntimeException(cmd.getStatusMsg());
			}
		}
		else {
			CreateDataCmd cmd = new CreateDataCmd(address, datatype);
			if (!cmd.applyTo(program)) {
				throw new RuntimeException(cmd.getStatusMsg());
			}
		}
		return program.getListing().getDefinedDataAt(address);
	}

	protected boolean setPlateComment(Program program, Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.PLATE_COMMENT, comment);
		return cmd.applyTo(program);
	}

	protected Function createFunction(Program program, Address entryPoint) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(entryPoint);
		cmd.applyTo(program);
		return program.getListing().getFunctionAt(entryPoint);
	}

	protected Address find(Program program, Address start, byte[] values, TaskMonitor monitor) {
		return program.getMemory().findBytes(start, values, null, true, monitor);
	}

}
