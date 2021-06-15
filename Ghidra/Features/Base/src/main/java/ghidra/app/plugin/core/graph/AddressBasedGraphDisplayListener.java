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
package ghidra.app.plugin.core.graph;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import docking.widgets.EventTrigger;
import ghidra.app.events.*;
import ghidra.app.nav.NavigationUtils;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.service.graph.*;
import ghidra.util.Swing;

/**
 * Base class for GraphDisplay listeners whose nodes represent addresses.
 */
public abstract class AddressBasedGraphDisplayListener
		implements GraphDisplayListener, PluginEventListener, DomainObjectListener {

	protected PluginTool tool;
	protected GraphDisplay graphDisplay;
	protected Program program;
	private SymbolTable symbolTable;
	private String name;
	private static AtomicInteger instanceCount = new AtomicInteger(1);

	public AddressBasedGraphDisplayListener(PluginTool tool, Program program,
			GraphDisplay display) {
		this.tool = tool;
		this.program = program;
		this.symbolTable = program.getSymbolTable();
		this.graphDisplay = display;
		name = getClass().getSimpleName() + instanceCount.getAndAdd(1);
		tool.addListenerForAllPluginEvents(this);
		program.addListener(this);
	}

	@Override
	public void graphClosed() {
		dispose();
	}

	@Override
	public void locationFocusChanged(AttributedVertex vertex) {
		Address address = getAddress(vertex);
		if (address != null) {
			ProgramLocation location = new ProgramLocation(program, address);
			tool.firePluginEvent(new ProgramLocationPluginEvent(name, location, program));
		}
	}

	@Override
	public void selectionChanged(Set<AttributedVertex> vertices) {
		AddressSet addressSet = getAddresses(vertices);
		if (addressSet != null) {
			ProgramSelection selection = new ProgramSelection(addressSet);
			ProgramSelectionPluginEvent event =
				new ProgramSelectionPluginEvent(name, selection, program);
			tool.firePluginEvent(event);
		}
	}

	@Override
	public void eventSent(PluginEvent event) {
		if (Objects.equals(event.getSourceName(), name)) {
			return;
		}

		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			if (isMyProgram(ev.getProgram())) {
				graphDisplay.close();
				dispose();
			}
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
			if (isMyProgram(ev.getProgram())) {
				ProgramLocation location = ev.getLocation();
				AttributedVertex vertex = getVertex(location.getAddress());
				// update graph location, but tell it not to send out event
				graphDisplay.setFocusedVertex(vertex, EventTrigger.INTERNAL_ONLY);
			}
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
			if (isMyProgram(ev.getProgram())) {
				ProgramSelection selection = ev.getSelection();
				Set<AttributedVertex> selectedVertices = getVertices(selection);
				if (selectedVertices != null) {
					// since we are responding to an event, tell the GraphDisplay not to send event
					graphDisplay.selectVertices(selectedVertices, EventTrigger.INTERNAL_ONLY);
				}
			}
		}
	}

	public AttributedVertex getVertex(Address address) {
		if (address == null) {
			return null;
		}
		String id = getVertexId(address);
		if (id == null) {
			return null;
		}

		return graphDisplay.getGraph().getVertex(id);
	}

	protected String getVertexId(Address address) {
		// vertex ids for external locations use symbol names since they don't have meaningful addresses.
		if (address.isExternalAddress()) {
			Symbol s = symbolTable.getPrimarySymbol(address);
			return s.getName(true);
		}
		return address.toString();
	}

	protected Address getAddress(String vertexIdString) {
		Address address = program.getAddressFactory().getAddress(vertexIdString);
		if (address != null) {
			return address;
		}

		// the vertex id was not an address, see if it is an external symbol name
		int index = vertexIdString.indexOf(Namespace.DELIMITER);
		if (index <= 0) {
			return null;
		}
		String namespaceName = vertexIdString.substring(0, index);
		String symbolName = vertexIdString.substring(index + 2);
		Namespace namespace = symbolTable.getNamespace(namespaceName, null);
		if (namespace == null) {
			return null;
		}

		List<Symbol> symbols = symbolTable.getSymbols(symbolName, namespace);
		if (symbols.isEmpty()) {
			return null;
		}

		// There should only be one external symbol with the same name.
		// Since externals are not shown in the listing, we are going to do a hack and try
		// and navigate to a "fake" function if one exists. A "fake" function in Ghidra is just
		// an indirect pointer to the external function. If such a pointer exists, Ghidra marks
		// up the location with the function signature.
		Address symbolAddress = symbols.get(0).getAddress();
		if (symbolAddress.isExternalAddress()) {
			Address[] externalLinkageAddresses =
				NavigationUtils.getExternalLinkageAddresses(program, symbolAddress);
			// If this is a "fake" function situation, then there should only be one address
			if (externalLinkageAddresses.length == 1) {
				symbolAddress = externalLinkageAddresses[0];
			}
		}
		return symbolAddress;
	}

	protected Address getAddress(AttributedVertex vertex) {
		if (vertex == null) {
			return null;
		}
		return getAddress(vertex.getId());
	}

	protected abstract Set<AttributedVertex> getVertices(AddressSetView selection);

	protected abstract AddressSet getAddresses(Set<AttributedVertex> vertexIds);

	private boolean isMyProgram(Program p) {
		return p == program;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!(ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_SYMBOL_RENAMED) ||
			ev.containsEvent(ChangeManager.DOCR_SYMBOL_REMOVED))) {
			return;
		}

		for (DomainObjectChangeRecord record : ev) {
			if (record instanceof ProgramChangeRecord) {
				ProgramChangeRecord programRecord = (ProgramChangeRecord) record;
				Address address = programRecord.getStart();

				if (record.getEventType() == ChangeManager.DOCR_SYMBOL_RENAMED) {
					handleSymbolAddedOrRenamed(address, (Symbol) programRecord.getObject());
				}
				else if (record.getEventType() == ChangeManager.DOCR_SYMBOL_ADDED) {
					handleSymbolAddedOrRenamed(address, (Symbol) programRecord.getNewValue());
				}
				else if (record.getEventType() == ChangeManager.DOCR_SYMBOL_REMOVED) {
					handleSymbolRemoved(address);
				}
			}
		}
	}

	private void handleSymbolAddedOrRenamed(Address address, Symbol symbol) {
		AttributedVertex vertex = getVertex(address);
		if (vertex == null) {
			return;
		}
		graphDisplay.updateVertexName(vertex, symbol.getName());
	}

	private void handleSymbolRemoved(Address address) {
		AttributedVertex vertex = getVertex(address);
		if (vertex == null) {
			return;
		}
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		String displayName = symbol == null ? address.toString() : symbol.getName();
		graphDisplay.updateVertexName(vertex, displayName);
	}

	@Override
	public void dispose() {
		Swing.runLater(() -> tool.removeListenerForAllPluginEvents(this));
		program.removeListener(this);
	}

}
