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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import java.util.HashMap;
import java.util.Objects;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TraceCallTreeLogModel
		extends ThreadedTableModelStub<TraceCallTreeLogModel.TraceCallTreeLogObject> {
	private static class DynamicAddressColumn
			extends AbstractDynamicTableColumn<TraceCallTreeLogObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Dynamic Address";
		}

		@Override
		public Address getValue(TraceCallTreeLogObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.dynamicAddress();
		}
	}

	private static class MessageColumn
			extends AbstractDynamicTableColumn<TraceCallTreeLogObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Message";
		}

		@Override
		public String getValue(TraceCallTreeLogObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.log();
		}
	}

	private static class SnapColumn
			extends AbstractDynamicTableColumn<TraceCallTreeLogObject, Long, Object> {

		@Override
		public String getColumnName() {
			return "Snap";
		}

		@Override
		public Long getValue(TraceCallTreeLogObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.snap();
		}
	}

	private static class StaticAddressColumn
			extends AbstractDynamicTableColumn<TraceCallTreeLogObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Static Address";
		}

		@Override
		public Address getValue(TraceCallTreeLogObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.staticAddress();
		}
	}

	public record TraceCallTreeLogObject(Trace trace, String log, long snap, Address dynamicAddress,
			Address staticAddress) {
		public TraceCallTreeLogObject {
			Objects.requireNonNull(log);
		}
	}

	private static class TraceColumn
			extends AbstractDynamicTableColumn<TraceCallTreeLogObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Trace";
		}

		@Override
		public String getValue(TraceCallTreeLogObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.trace().getName();
		}
	}

	record LogKey(String traceName, Address dynamicAddress, long snap) {}

	HashMap<LogKey, TraceCallTreeLogObject> logs;

	protected TraceCallTreeLogModel(TraceCallTreePlugin plugin) {
		super("Trace Call Tree Log Model", plugin.getTool());
		logs = new HashMap<>();
	}

	void clear() {
		logs.clear();
		reload();
	}

	@Override
	protected TableColumnDescriptor<TraceCallTreeLogObject> createTableColumnDescriptor() {
		final TableColumnDescriptor<TraceCallTreeLogObject> descriptor =
			new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new TraceColumn());
		descriptor.addVisibleColumn(new SnapColumn());
		descriptor.addVisibleColumn(new MessageColumn());
		descriptor.addVisibleColumn(new DynamicAddressColumn());
		descriptor.addVisibleColumn(new StaticAddressColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<TraceCallTreeLogObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(logs.values());
	}

	void log(Trace trace, String msg, long snap, Address staticAddress, Address dynamicAddress) {
		final TraceCallTreeLogObject log =
			new TraceCallTreeLogObject(trace, msg, snap, dynamicAddress, staticAddress);
		final LogKey key = new LogKey(trace.getName(), dynamicAddress, snap);
		logs.remove(key);
		logs.put(key, log);
		reload();
	}

	void resolve(Trace trace, long snap, Address dynamicAddress) {
		final LogKey key = new LogKey(trace.getName(), dynamicAddress, snap);
		logs.remove(key);
		reload();
	}
}
