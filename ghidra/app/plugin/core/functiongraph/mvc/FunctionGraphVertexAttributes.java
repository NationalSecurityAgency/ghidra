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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.awt.Color;
import java.awt.Point;
import java.util.*;
import java.util.Map.Entry;

import org.jdom.Element;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMap;
import ghidra.util.*;

/**
 * A class to store user graph setting information, such as layout positions, grouping information
 * and vertex color information.
 * 
 * <P>Note: color information for a given address is stored using the {@link ColorizingService}.
 * This class will store color information for the vertex itself.
 */
public class FunctionGraphVertexAttributes {

	public static final String LOCATION_PROPERTY_NAME = "VERTEX_LOCATION";
	public static final String COLOR_PROPERTY_NAME = "VERTEX_COLOR";
	public static final String GROUP_SETTINGS_PROPERTY_NAME = "VERTEX_GROUP_SETTINGS";
	public static final String REGROUP_SETTINGS_PROPERTY_NAME = "VERTEX_REGROUP_SETTINGS";
	private static final String GROUP_LOCATION_PROPERTY_NAME = "GROUP_VERTEX_LOCATION";

	private Map<Address, Saveable> colorUpdateMap = new HashMap<>();
	private Map<Address, Saveable> locationUpdateMap = new HashMap<>();
	private Map<Address, Saveable> groupLocationUpdateMap = new HashMap<>();
	private Map<Address, Saveable> groupedSettingsUpdateMap = new HashMap<>();
	private Map<Address, Saveable> regroupSettingsUpdateMap = new HashMap<>();

	private ProgramUserData programUserData;

	public FunctionGraphVertexAttributes(Program program) {
		programUserData = program.getProgramUserData();
	}

	public Map<FGVertex, Point> getVertexLocations(FunctionGraph functionGraph) {
		ObjectPropertyMap vertexLocationropertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				LOCATION_PROPERTY_NAME, SaveablePoint.class, false);

		ObjectPropertyMap groupVertexLocationropertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				GROUP_LOCATION_PROPERTY_NAME, SaveablePoint.class, false);

		return getVertexLocationsFromPropertyMaps(functionGraph, vertexLocationropertyMap,
			groupVertexLocationropertyMap);
	}

	private Map<FGVertex, Point> getVertexLocationsFromPropertyMaps(FunctionGraph functionGraph,
			ObjectPropertyMap vertexLocationPropertyMap,
			ObjectPropertyMap groupVertexLocationPropertyMap) {

		Map<FGVertex, Point> map = new HashMap<>();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			SaveablePoint saveablePoint = getPointFromPropertyMap(vertex, vertexLocationPropertyMap,
				groupVertexLocationPropertyMap);
			if (saveablePoint != null) {
				Point point = saveablePoint.getPoint();
				map.put(vertex, point);
			}
		}
		return map;
	}

	private SaveablePoint getPointFromPropertyMap(FGVertex vertex,
			ObjectPropertyMap vertexLocationPropertyMap,
			ObjectPropertyMap groupVertexLocationPropertyMap) {

		Address address = vertex.getVertexAddress();
		if (vertex instanceof GroupedFunctionGraphVertex) {
			if (groupVertexLocationPropertyMap == null) {
				return null;
			}

			return (SaveablePoint) groupVertexLocationPropertyMap.getObject(address);
		}

		if (vertexLocationPropertyMap == null) {
			return null;
		}
		return (SaveablePoint) vertexLocationPropertyMap.getObject(address);
	}

	public Element getGroupedVertexSettings(FunctionGraph functionGraph) {
		ObjectPropertyMap propertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				GROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, false);
		if (propertyMap == null) {
			return null;
		}

		FGVertex rootVertex = functionGraph.getRootVertex();
		Address entryPoint = rootVertex.getVertexAddress();
		SaveableXML saveableXML = (SaveableXML) propertyMap.getObject(entryPoint);
		if (saveableXML != null) {
			return saveableXML.getElement();
		}

		return null;
	}

	public Element getRegroupVertexSettings(FunctionGraph functionGraph) {
		ObjectPropertyMap propertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				REGROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, false);
		if (propertyMap == null) {
			return null;
		}

		FGVertex rootVertex = functionGraph.getRootVertex();
		Address entryPoint = rootVertex.getVertexAddress();
		SaveableXML saveableXML = (SaveableXML) propertyMap.getObject(entryPoint);
		if (saveableXML != null) {
			return saveableXML.getElement();
		}

		return null;
	}

	public Map<FGVertex, Color> getVertexColors(FunctionGraph functionGraph) {
		ObjectPropertyMap propertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				COLOR_PROPERTY_NAME, SaveableColor.class, false);
		if (propertyMap == null) {
			return Collections.emptyMap();
		}

		Map<FGVertex, Color> map = new HashMap<>();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			AddressSetView codeBlock = vertex.getAddresses();
			Address minAddress = codeBlock.getMinAddress();
			SaveableColor saveableColor = (SaveableColor) propertyMap.getObject(minAddress);
			if (saveableColor != null) {
				Color color = saveableColor.getColor();
				map.put(vertex, color);
			}
		}
		return map;
	}

	/**
	 * Clears all vertex locations (including group vertex locations).
	 */
	public void clearVertexLocations(FunctionGraph functionGraph) {
		locationUpdateMap.clear(); // clear any unsaved changes
		groupLocationUpdateMap.clear();

		int transactionID = programUserData.startTransaction();
		try {
			ObjectPropertyMap vertexLocationPropertyMap =
				programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
					LOCATION_PROPERTY_NAME, SaveablePoint.class, false);
			clearMap(vertexLocationPropertyMap, functionGraph);

			ObjectPropertyMap groupVertexLocationPropertyMap =
				programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
					GROUP_LOCATION_PROPERTY_NAME, SaveablePoint.class, false);
			clearMap(groupVertexLocationPropertyMap, functionGraph);
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	private void clearMap(ObjectPropertyMap propertyMap, FunctionGraph functionGraph) {
		if (propertyMap == null) {
			return; // nothing to do
		}

		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			AddressSetView codeBlock = vertex.getAddresses();
			Address minAddress = codeBlock.getMinAddress();
			propertyMap.remove(minAddress);
		}
	}

	/**
	 * Note: this method does not clear group vertex locations.
	 */
	public void clearGroupSettings(FunctionGraph functionGraph) {
		groupedSettingsUpdateMap.clear(); // clear any unsaved changes

		int transactionID = programUserData.startTransaction();
		try {
			ObjectPropertyMap propertyMap =
				programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
					GROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, false);

			if (propertyMap == null) {
				return; // nothing to do
			}

			FGVertex rootVertex = functionGraph.getRootVertex();
			propertyMap.remove(rootVertex.getVertexAddress());
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	public void clearRegroupSettings(FunctionGraph functionGraph) {
		regroupSettingsUpdateMap.clear(); // clear any unsaved changes

		int transactionID = programUserData.startTransaction();
		try {
			ObjectPropertyMap propertyMap =
				programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
					REGROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, false);

			if (propertyMap == null) {
				return; // nothing to do
			}

			FGVertex rootVertex = functionGraph.getRootVertex();
			propertyMap.remove(rootVertex.getVertexAddress());
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	public void clearAllPropertiesForAddresses(AddressSetView addresses) {
		int transactionID = programUserData.startTransaction();
		try {
			List<PropertyMap> properties =
				programUserData.getProperties(FunctionGraphPlugin.class.getSimpleName());
			for (PropertyMap propertyMap : properties) {
				clearAllPropertiesForAddressRange(propertyMap, addresses);
			}
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	public void clearPropertyForAddresses(String propertyName, AddressSetView addresses) {
		int transactionID = programUserData.startTransaction();
		try {
			List<PropertyMap> properties =
				programUserData.getProperties(FunctionGraphPlugin.class.getSimpleName());
			for (PropertyMap propertyMap : properties) {
				if (propertyMap.getName().equals(propertyName)) {
					clearAllPropertiesForAddressRange(propertyMap, addresses);
					return;
				}
			}
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	private void clearAllPropertiesForAddressRange(PropertyMap propertyMap,
			AddressSetView addresses) {
		AddressIterator iterator = addresses.getAddresses(true);
		for (; iterator.hasNext();) {
			Address address = iterator.next();
			propertyMap.remove(address);
		}
	}

	public void save() {
		int transactionID = programUserData.startTransaction();
		try {

			if (!colorUpdateMap.isEmpty()) {
				ObjectPropertyMap propertyMap =
					programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
						COLOR_PROPERTY_NAME, SaveableColor.class, true);
				saveMap(colorUpdateMap, propertyMap);
			}

			if (!locationUpdateMap.isEmpty()) {
				ObjectPropertyMap propertyMap =
					programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
						LOCATION_PROPERTY_NAME, SaveablePoint.class, true);
				saveMap(locationUpdateMap, propertyMap);
			}

			if (!groupLocationUpdateMap.isEmpty()) {
				ObjectPropertyMap propertyMap =
					programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
						GROUP_LOCATION_PROPERTY_NAME, SaveablePoint.class, true);
				saveMap(groupLocationUpdateMap, propertyMap);
			}

			if (!groupedSettingsUpdateMap.isEmpty()) {
				ObjectPropertyMap propertyMap =
					programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
						GROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, true);
				saveMap(groupedSettingsUpdateMap, propertyMap);
			}

			if (!regroupSettingsUpdateMap.isEmpty()) {
				ObjectPropertyMap propertyMap =
					programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
						REGROUP_SETTINGS_PROPERTY_NAME, SaveableXML.class, true);
				saveMap(regroupSettingsUpdateMap, propertyMap);
			}
		}
		finally {
			programUserData.endTransaction(transactionID);
		}
	}

	private void saveMap(Map<Address, Saveable> map, ObjectPropertyMap propertyMap) {
		Set<Entry<Address, Saveable>> entrySet = map.entrySet();
		for (Entry<Address, Saveable> entry : entrySet) {
			Address key = entry.getKey();
			Saveable value = entry.getValue();

			if (value instanceof LazySaveableXML) {
				if (((LazySaveableXML) value).isEmpty()) {
					// don't save empty data
					continue;
				}
			}

			if (value != null) {
				propertyMap.add(key, value);
			}
			else {
				propertyMap.remove(key);
			}
		}
	}

	public Color getVertexColor(Address address) {
		ObjectPropertyMap propertyMap =
			programUserData.getObjectProperty(FunctionGraphPlugin.class.getSimpleName(),
				COLOR_PROPERTY_NAME, SaveableColor.class, false);
		if (propertyMap == null) {
			return null;
		}

		SaveableColor saveable = (SaveableColor) propertyMap.getObject(address);
		if (saveable == null) {
			return null;
		}

		return saveable.getColor();
	}

	public void clearVertexColor(Address address) {
		colorUpdateMap.put(address, null);
	}

	public void clearVertexLocation(FGVertex vertex) {
		Address address = vertex.getVertexAddress();
		if (vertex instanceof GroupedFunctionGraphVertex) {
			groupLocationUpdateMap.put(address, null);
		}
		else {
			locationUpdateMap.put(address, null);
		}
	}

	public void clearGroupedVertexSettings(Address address) {
		groupedSettingsUpdateMap.put(address, null);
	}

	public void clearRegroupVertexSettign(Address address) {
		regroupSettingsUpdateMap.put(address, null);
	}

	public void putVertexColor(Address address, Color color) {
		colorUpdateMap.put(address, new SaveableColor(color));
	}

	public void putVertexLocation(FGVertex vertex, Point point) {
		Address vertexAddress = vertex.getVertexAddress();

		Point pointCopy = new Point(point); // points are not immutable, so copy the given one
		if (vertex instanceof GroupedFunctionGraphVertex) {
			groupLocationUpdateMap.put(vertexAddress, new SaveablePoint(pointCopy));
		}
		else {
			locationUpdateMap.put(vertexAddress, new SaveablePoint(pointCopy));
		}
	}

	public void putGroupedVertexSettings(FunctionGraph functionGraph, SaveableXML saveableXML) {
		FGVertex rootVertex = functionGraph.getRootVertex();
		Address entryPoint = rootVertex.getVertexAddress();
		groupedSettingsUpdateMap.put(entryPoint, saveableXML);
	}

	public void putRegroupSettings(FunctionGraph functionGraph, SaveableXML saveableXML) {
		FGVertex rootVertex = functionGraph.getRootVertex();
		Address entryPoint = rootVertex.getVertexAddress();
		regroupSettingsUpdateMap.put(entryPoint, saveableXML);
	}
}
