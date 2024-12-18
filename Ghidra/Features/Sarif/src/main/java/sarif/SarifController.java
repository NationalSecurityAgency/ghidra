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
package sarif;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.util.*;

import com.contrastsecurity.sarif.*;

import docking.widgets.table.ObjectSelectedListener;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import sarif.handlers.SarifResultHandler;
import sarif.handlers.SarifRunHandler;
import sarif.handlers.run.SarifGraphRunHandler;
import sarif.managers.ProgramSarifMgr;
import sarif.model.SarifDataFrame;
import sarif.view.ImageArtifactDisplay;
import sarif.view.SarifResultsTableProvider;

/**
 * Controller for handling interactions between the SARIF log file and Ghidra
 */
public class SarifController implements ObjectSelectedListener<Map<String, Object>> {

	private SarifPlugin plugin;
	private Program program;

	private ColorizingService coloringService;
	private BookmarkManager bookmarkManager;
	private ProgramSarifMgr programManager;

	private Set<SarifResultsTableProvider> providers = new HashSet<>();
	public Set<ImageArtifactDisplay> artifacts = new HashSet<>();
	public Set<GraphDisplay> graphs = new HashSet<>();

	private Class<? extends SarifGraphRunHandler> defaultGraphHandler = SarifGraphRunHandler.class;
	private boolean useOverlays;

	public Set<SarifResultHandler> getSarifResultHandlers() {
		Set<SarifResultHandler> set = new HashSet<>();
		set.addAll(ClassSearcher.getInstances(SarifResultHandler.class));
		return set;
	}

	public Set<SarifRunHandler> getSarifRunHandlers() {
		Set<SarifRunHandler> set = new HashSet<>();
		set.addAll(ClassSearcher.getInstances(SarifRunHandler.class));
		return set;
	}

	public SarifController(Program program, SarifPlugin plugin) {
		this.program = program;
		this.plugin = plugin;
		this.coloringService = plugin.getTool().getService(ColorizingService.class);
		this.programManager = new ProgramSarifMgr(program, new MessageLog());
	}

	public SarifController(ProgramSarifMgr manager) {
		this.program = null;
		this.plugin = null;
		this.coloringService = null; // plugin.getTool().getService(ColorizingService.class);
		this.programManager = manager;
	}

	public void dispose() {
		Set<SarifResultsTableProvider> copyProviders = new HashSet<>();
		copyProviders.addAll(providers);
		for (SarifResultsTableProvider p : copyProviders) {
			p.dispose();
		}
		Set<ImageArtifactDisplay> copyArtifacts = new HashSet<>();
		copyArtifacts.addAll(artifacts);
		for (ImageArtifactDisplay a : copyArtifacts) {
			a.dispose();
		}
		for (GraphDisplay g : graphs) {
			g.close();
		}
	}

	public void showTable(boolean makeVisible) {
		for (SarifResultsTableProvider p : providers) {
			p.setVisible(makeVisible);
		}
	}

	public void showTable(String logName, SarifSchema210 sarif) {
		SarifDataFrame df = new SarifDataFrame(sarif, this, false);
		SarifResultsTableProvider provider =
			new SarifResultsTableProvider(logName, getPlugin(), this, df);
		provider.filterTable.addSelectionListener(this);
		provider.addToTool();
		provider.setVisible(true);
		provider.setTitle(logName);
		if (!providers.contains(provider)) {
			providers.add(provider);
		}
	}

	public void showImage(String key, BufferedImage img) {
		if (getPlugin().displayArtifacts()) {
			ImageArtifactDisplay display =
				new ImageArtifactDisplay(getPlugin().getTool(), key, "Sarif Parse", img);
			display.setVisible(true);
			artifacts.add(display);
		}
	}

	public void showGraph(AttributedGraph graph) {
		try {
			PluginTool tool = this.getPlugin().getTool();
			GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
			boolean append = getPlugin().appendToGraph();
			GraphDisplay display = service.getDefaultGraphDisplay(append, null);
			GraphDisplayOptions graphOptions = new GraphDisplayOptions(new EmptyGraphType());
			graphOptions.setMaxNodeCount(getPlugin().getGraphSize());

			if (getPlugin().displayGraphs()) {
				display.setGraph(graph, graphOptions, graph.getDescription(), append, null);
				SarifGraphDisplayListener listener =
					new SarifGraphDisplayListener(this, display, graph);
				display.setGraphDisplayListener(listener);
				graphs.add(display);
			}
		}
		catch (GraphException | CancelledException e) {
			Msg.error(this, "showGraph failed " + e.getMessage());
		}
	}

	/**
	 * If a results has "listing/<something>" in a SARIF result, this handles
	 * defining our custom API for those
	 */
	public void handleListingAction(Run run, Result result, String key, Object value) {
		List<Address> addrs = getListingAddresses(run, result);
		for (Address addr : addrs) {
			switch (key) {
				case "comment":
					/*
					 * {@link program.model.listing.CodeUnit}
					 */
					String comment = (String) value;
					getProgram().getListing().setComment(addr, CodeUnit.PLATE_COMMENT, comment);
					break;
				case "highlight":
					Color color = Color.decode((String) value);
					coloringService.setBackgroundColor(addr, addr, color);
					break;
				case "bookmark":
					String bookmark = (String) value;
					getProgram().getBookmarkManager()
							.setBookmark(addr, "Sarif", result.getRuleId(), bookmark);
					break;
			}
		}
	}

	public void colorBackground(AddressSetView set, Color color) {
		coloringService.setBackgroundColor(set, color);
	}

	public void colorBackground(Address addr, Color color) {
		coloringService.setBackgroundColor(addr, addr, color);
	}

	/**
	 * Get listing addresses associated with a result
	 */
	public List<Address> getListingAddresses(Run run, Result result) {
		List<Address> addrs = new ArrayList<>();
		if (result.getLocations() != null && result.getLocations().size() > 0) {
			List<Location> locations = result.getLocations();
			for (Location loc : locations) {
				Address addr = locationToAddress(run, loc);
				if (addr != null) {
					addrs.add(addr);
				}
			}
		}
		return addrs;
	}

	public Address locationToAddress(Run run, Location loc) {
		return SarifUtils.locationToAddress(loc, program, useOverlays);
	}

	/**
	 * Pull the text information from a State object
	 * @param stateKey
	 * @return The text value or empty string if key not found.
	 */
	public String getStateText(State state, String stateKey) {
		String result = "";

		Map<String, MultiformatMessageString> state_mappings = state.getAdditionalProperties();

		for (Map.Entry<String, MultiformatMessageString> pair : state_mappings.entrySet()) {
			if (pair.getKey().equalsIgnoreCase(stateKey)) {
				result = pair.getValue().getText();
				break;
			}
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void objectSelected(Map<String, Object> row) {
		if (row != null) {
			if (row.containsKey("CodeFlows")) {
				for (List<Address> flow : (List<List<Address>>) row.get("CodeFlows")) {
					this.getPlugin().makeSelection(flow);
				}
			}
			if (row.containsKey("Graphs")) {
				for (AttributedGraph graph : (List<AttributedGraph>) row.get("Graphs")) {
					this.showGraph(graph);
				}
			}
		}
	}

	public void removeProvider(SarifResultsTableProvider provider) {
		providers.remove(provider);
	}

	public ProgramSarifMgr getProgramSarifMgr() {
		return programManager;
	}

	public Program getProgram() {
		return program;
	}

	public void setProgram(Program program) {
		this.program = program;
		this.bookmarkManager = program.getBookmarkManager();
		bookmarkManager.defineType("Sarif", SarifPlugin.SARIF_ICON, Color.pink, 0);
	}

	public SarifPlugin getPlugin() {
		return plugin;
	}

	public void setSelection(Set<AttributedVertex> vertices) {
		for (SarifResultsTableProvider provider : providers) {
			provider.setSelection(vertices);
		}
	}

	public Class<? extends SarifGraphRunHandler> getDefaultGraphHander() {
		return defaultGraphHandler;
	}

	@SuppressWarnings("unchecked")
	public void setDefaultGraphHander(Class<? extends SarifGraphRunHandler> clazz) {
		defaultGraphHandler = clazz;
	}

	public void setUseOverlays(boolean useOverlays) {
		this.useOverlays = useOverlays;
	}

}
