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
package ghidra.app.plugin.core.debug.gui.slice;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** JSON persistence for slice trees. */
final class SliceSession {
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	enum UnitKind {
		INSTRUCTION, DATA
	}

	static class Session {
		int version = 1;
		String trace;
		SliceDirection direction;
		List<Node> nodes = new ArrayList<>();

		public long totalSize() {
			return nodes.stream().mapToLong(Node::totalSize).sum();
		}
	}

	static class Node {
		SliceEdgeType edgeType;
		UnitKind unitKind;
		long snap;
		String address;
		int length;
		boolean displaySnap;
		boolean checked;
		boolean expanded;
		List<Node> children = new ArrayList<>();

		public long totalSize() {
			return 1 + children.stream().mapToLong(Node::totalSize).sum();
		}
	}

	private SliceSession() {
	}

	static String write(Session session) {
		return GSON.toJson(session);
	}

	static Session read(String json) throws IOException {
		Session session;
		try {
			session = GSON.fromJson(json, Session.class);
		}
		catch (RuntimeException e) {
			throw new IOException("Invalid slice session JSON", e);
		}
		if (session == null || session.version != 1 || session.trace == null ||
			session.nodes == null) {
			throw new IOException("Unsupported or incomplete slice session file");
		}
		return session;
	}

	static Node saveNode(AbstractSliceNode node) {
		if (!(node instanceof UnitSliceNode<?> unitNode)) {
			throw new IllegalArgumentException("Slice tree contains a non-unit node");
		}
		Node saved = new Node();
		saved.edgeType = unitNode.getEdgeType();
		saved.unitKind = unitNode.unit instanceof Instruction
				? UnitKind.INSTRUCTION
				: UnitKind.DATA;
		saved.snap = unitNode.getSnap();
		saved.address = unitNode.getAddress().toString();
		saved.length = unitNode.unit.getLength();
		saved.displaySnap = unitNode.displaySnap;
		saved.checked = unitNode.isChecked();
		saved.expanded = unitNode.isExpanded();
		for (var child : unitNode.getChildren()) {
			saved.children.add(saveNode((AbstractSliceNode) child));
		}
		return saved;
	}

	static AbstractSliceNode restoreNode(AbstractSliceNode parent, Trace trace, Node saved,
			PluginTool tool, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.checkCancelled();

		Address address;
		try {
			address = trace.getBaseAddressFactory().getAddress(saved.address);
		}
		catch (RuntimeException e) {
			throw new IOException("Invalid address in slice session: " + saved.address, e);
		}
		if (address == null || saved.length < 1 || saved.edgeType == null ||
			saved.unitKind == null || saved.children == null) {
			throw new IOException("Invalid node in slice session");
		}

		CodeUnit unit = restoreUnit(trace, saved, address, monitor);
		DebuggerAddressTranslator ms = tool.getService(DebuggerStaticMappingService.class);
		UnitSliceNode<?> node =
			parent.newUnitNode(saved.edgeType, unit, saved.snap, saved.displaySnap, ms);
		node.setChecked(saved.checked);
		node.setExpanded(saved.expanded);

		monitor.incrementProgress(1);

		for (Node child : saved.children) {
			node.add(restoreNode(node, trace, child, tool, monitor));
		}
		return node;
	}

	private static CodeUnit restoreUnit(Trace trace, Node saved, Address address,
			TaskMonitor monitor) throws IOException, CancelledException {
		monitor.checkCancelled();
		return switch (saved.unitKind) {
			case DATA -> {
				Address max = address.add(saved.length - 1);
				Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, saved.snap,
					new AddressRangeImpl(address, max));
				if (data.getLength() != saved.length) {
					throw new IOException("Data length changed at " + address);
				}
				yield data;
			}
			case INSTRUCTION -> {
				Register contextRegister = trace.getBaseLanguage().getContextBaseRegister();
				TraceMemorySpace registers =
					SliceAnalysis.INSTANCE.getEventThreadRegisters(trace, saved.snap);
				RegisterValue context = registers == null || contextRegister == null ? null
						: registers.getValue(saved.snap, contextRegister);
				Instruction instruction = SliceAnalysis.INSTANCE.getOrDisassemble(trace, saved.snap,
					address, context);
				if (instruction == null || instruction.getLength() != saved.length) {
					throw new IOException("Instruction length changed at " + address);
				}
				yield instruction;
			}
		};
	}
}
