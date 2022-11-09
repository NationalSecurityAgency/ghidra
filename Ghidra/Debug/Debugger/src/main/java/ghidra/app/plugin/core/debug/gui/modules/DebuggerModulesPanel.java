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
package ghidra.app.plugin.core.debug.gui.modules;

import java.util.*;

import javax.swing.event.ListSelectionEvent;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

public class DebuggerModulesPanel extends AbstractObjectsTableBasedPanel<TraceObjectModule> {

	private static class ModuleBaseColumn extends AbstractTraceValueObjectAddressColumn {
		public ModuleBaseColumn() {
			super(TargetModule.RANGE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Base";
		}

		@Override
		protected Address fromRange(AddressRange range) {
			return range.getMinAddress();
		}
	}

	private static class ModuleMaxColumn extends AbstractTraceValueObjectAddressColumn {
		public ModuleMaxColumn() {
			super(TargetModule.RANGE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Max";
		}

		@Override
		protected Address fromRange(AddressRange range) {
			return range.getMaxAddress();
		}
	}

	private static class ModuleNameColumn extends TraceValueObjectAttributeColumn<String> {
		public ModuleNameColumn() {
			super(TargetModule.MODULE_NAME_ATTRIBUTE_NAME, String.class);
		}

		@Override
		public String getColumnName() {
			return "Name";
		}
	}

	private static class ModulePathColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getValue().getCanonicalPath().toString();
		}
	}

	private static class ModuleLengthColumn extends AbstractTraceValueObjectLengthColumn {
		public ModuleLengthColumn() {
			super(TargetModule.RANGE_ATTRIBUTE_NAME);
		}

		@Override
		public String getColumnName() {
			return "Length";
		}
	}

	private static class ModuleTableModel extends ObjectTableModel {
		protected ModuleTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addHiddenColumn(new ModulePathColumn());
			descriptor.addVisibleColumn(new ModuleBaseColumn(), 1, true);
			descriptor.addVisibleColumn(new ModuleMaxColumn());
			descriptor.addVisibleColumn(new ModuleNameColumn());
			descriptor.addVisibleColumn(new ModuleLengthColumn());
			return descriptor;
		}
	}

	protected static Set<TraceModule> getSelectedModulesFromContext(
			DebuggerObjectActionContext ctx) {
		Set<TraceModule> result = new HashSet<>();
		for (TraceObjectValue value : ctx.getObjectValues()) {
			TraceObject child = value.getChild();
			TraceObjectModule module = child.queryInterface(TraceObjectModule.class);
			if (module != null) {
				result.add(module);
				continue;
			}
			TraceObjectSection section = child.queryInterface(TraceObjectSection.class);
			if (section != null) {
				result.add(section.getModule());
				continue;
			}
		}
		return result;
	}

	protected static Set<TraceSection> getSelectedSectionsFromContext(
			DebuggerObjectActionContext ctx) {
		Set<TraceSection> result = new HashSet<>();
		for (TraceObjectValue value : ctx.getObjectValues()) {
			TraceObject child = value.getChild();
			TraceObjectModule module = child.queryInterface(TraceObjectModule.class);
			if (module != null) {
				result.addAll(module.getSections());
				continue;
			}
			TraceObjectSection section = child.queryInterface(TraceObjectSection.class);
			if (section != null) {
				result.add(section);
				continue;
			}
		}
		return result;
	}

	public static AddressSetView getSelectedAddressesFromContext(DebuggerObjectActionContext ctx) {
		AddressSet result = new AddressSet();
		for (TraceObjectValue value : ctx.getObjectValues()) {
			TraceObject child = value.getChild();
			TraceObjectModule module = child.queryInterface(TraceObjectModule.class);
			if (module != null) {
				result.add(module.getRange());
				continue;
			}
			TraceObjectSection section = child.queryInterface(TraceObjectSection.class);
			if (section != null) {
				result.add(section.getRange());
				continue;
			}
		}
		return result;
	}

	protected static ModelQuery successorModules(TargetObjectSchema rootSchema, List<String> path) {
		TargetObjectSchema schema = rootSchema.getSuccessorSchema(path);
		return new ModelQuery(schema.searchFor(TargetModule.class, path, true));
	}

	private final DebuggerModulesProvider provider;

	public DebuggerModulesPanel(DebuggerModulesProvider provider) {
		super(provider.plugin, provider, TraceObjectModule.class);
		this.provider = provider;
	}

	@Override
	protected ObjectTableModel createModel(Plugin plugin) {
		return new ModuleTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TargetObjectSchema rootSchema = object.getRoot().getTargetSchema();
		List<String> seedPath = object.getCanonicalPath().getKeyList();
		List<String> processPath = rootSchema.searchForAncestor(TargetProcess.class, seedPath);
		if (processPath != null) {
			return successorModules(rootSchema, processPath);
		}
		List<String> containerPath =
			rootSchema.searchForSuitableContainer(TargetModule.class, seedPath);

		if (containerPath != null) {
			return successorModules(rootSchema, containerPath);
		}
		return successorModules(rootSchema, List.of());
	}

	public void setSelectedModules(Set<TraceModule> sel) {
		setSelected(sel);
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		super.valueChanged(e);
		if (e.getValueIsAdjusting()) {
			return;
		}
		provider.modulesPanelContextChanged();
	}
}
