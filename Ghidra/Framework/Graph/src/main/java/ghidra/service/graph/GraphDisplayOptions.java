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
package ghidra.service.graph;

import java.awt.Color;
import java.awt.Font;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.text.StringEscapeUtils;

import com.google.common.base.Splitter;

import docking.Tool;
import docking.options.editor.*;
import ghidra.framework.options.*;
import ghidra.util.HelpLocation;
import ghidra.util.WebColors;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Class for managing graph display options. This includes color options for each vertex
 * and edge type and shapes for vertex types.
 */
public class GraphDisplayOptions implements OptionsChangeListener {

	public static final GraphDisplayOptions DEFAULT =
		new GraphDisplayOptions(new EmptyGraphType());

	private static final String FONT = "Font";
	private static final String LABEL_POSITION = "Label Position";
	private static final String USE_ICONS = "Use Icons";
	private static final String DEFAULT_LAYOUT_ALGORITHM = "Default Layout Algorithm";
	private static final String EDGE_COLORS = "Edge Colors";
	private static final String VERTEX_COLORS = "Vertex Colors";
	private static final String VERTEX_SHAPES = "Vertex Shapes";
	private static final String MISCELLANEOUS_OPTIONS = "Miscellaneous";
	private static final String DEFAULT_VERTEX_COLOR = "Default Vertex Color";
	private static final String DEFAULT_EDGE_COLOR = "Default Edge Color";
	private static final String DEFAULT_VERTEX_SHAPE = "Default Vertex Shape";
	private static final String FAVORED_EDGE_TYPE = "Favored Edge Type";
	private static final String VERTEX_SELECTION_COLOR = "Selected Vertex Color";
	private static final String EDGE_SELECTION_COLOR = "Selected Edge Color";

	private static final String MAX_NODES_SIZE = "Max Graph Size";

	private GraphType graphType;

	private Map<String, Color> vertexColorMap = new HashMap<>();
	private Map<String, Color> edgeColorMap = new HashMap<>();
	private Map<String, VertexShape> vertexShapeMap = new HashMap<>();
	private Map<String, Integer> edgePriorityMap = new HashMap<>();
	private List<ChangeListener> changeListeners = new CopyOnWriteArrayList<>();

	private Color vertexSelectionColor = Color.green;
	private Color edgeSelectionColor = Color.green;
	private Color defaultVertexColor = Color.blue;
	private Color defaultEdgeColor = Color.blue;
	private String favoredEdgeType;

	private VertexShape defaultVertexShape = VertexShape.RECTANGLE;
	private String vertexLabelOverride = null;
	private String vertexColorOverride = null;
	private String vertexShapeOverride = null;
	private String edgeColorOverride = null;
	private final String rootOptionsName;
	private boolean registeredWithTool = false;
	private String defaultLayoutAlgorithmName = LayoutAlgorithmNames.MIN_CROSS_COFFMAN_GRAHAM;
	private boolean useIcons = true;
	private GraphLabelPosition labelPosition = GraphLabelPosition.SOUTH;
	private Font font = new Font("Dialog", Font.BOLD, 18);
	private int arrowLength = 15;

	private int maxNodeCount = 500; // graph display struggles with too many nodes

	/**
	 * Constructs a new GraphTypeDisplayOptions for the given {@link GraphType}
	 * @param graphType The {@link GraphType} for which to define display options
	 */
	public GraphDisplayOptions(GraphType graphType) {
		this(graphType, null);
	}

	/**
	 * Constructs a new GraphTypeDisplayOptions for the given {@link GraphType} and initializes
	 * from tool options. Note this form should only be used for display options on
	 * {@link GraphType}s that have options registered in the tool.
	 * @param graphType The {@link GraphType} for which to define display options
	 * @param tool the tool from which to initialize from {@link ToolOptions}
	 */
	public GraphDisplayOptions(GraphType graphType, Tool tool) {
		this.graphType = graphType;
		rootOptionsName = graphType.getOptionsName();
		List<String> edgeTypes = graphType.getEdgeTypes();
		if (!edgeTypes.isEmpty()) {
			favoredEdgeType = edgeTypes.iterator().next();
		}
		initializeEdgePriorities();
		initializeDefaults();
		initializeFromOptions(tool);
	}

	private void initializeEdgePriorities() {
		// initialize priorities based on the order they were defined
		for (String edgeType : graphType.getEdgeTypes()) {
			edgePriorityMap.put(edgeType, edgePriorityMap.size());
		}
	}

	protected void initializeDefaults() {
		// Overridden by subclass to define defaultValues
	}

	/**
	 * Adds a ChangeListener to be notified when display options change
	 * @param listener the listener to be notified.
	 */
	public void addChangeListener(ChangeListener listener) {
		changeListeners.add(listener);
	}

	/**
	 * Removes the listener so that it won't be notified of changes any longer
	 * @param listener the listener to be removed
	 */
	public void removeChangeListener(ChangeListener listener) {
		changeListeners.remove(listener);
	}

	/**
	 * Sets the default shape to be used by vertices that don't have a vertex type set
	 * @param shape the default vertex shape
	 */
	public void setDefaultVertexShape(VertexShape shape) {
		this.defaultVertexShape = Objects.requireNonNull(shape);
	}

	/**
	 * Sets the default color to be used by vertices that don't have a vertex type set
	 * @param color the default vertex shape
	 */
	public void setDefaultVertexColor(Color color) {
		this.defaultVertexColor = Objects.requireNonNull(color);
	}

	/**
	 * Sets the default color to be used by edges that don't have a edge type set
	 * @param color the default edge shape
	 */
	public void setDefaultEdgeColor(Color color) {
		this.defaultEdgeColor = Objects.requireNonNull(color);
	}

	/**
	 * Returns the default color for edges that don't have an edge type set
	 * @return the default color for edges that don't have an edge type set
	 */
	public Color getDefaultEdgeColor() {
		return defaultEdgeColor;
	}

	/**
	 * Returns the default color for vertices that don't have an vertex type set
	 * @return the default color for vertices that don't have an vertex type set
	 */
	public Color getDefaultVertexColor() {
		return defaultVertexColor;
	}

	/**
	 * Sets the attribute key that can be used to override the label text shown for the vertex.
	 * Normally, the vertex's name is shown as the label.
	 * @param attributeKey the attribute key that, if set, will be used to define the vertice's label
	 */
	public void setVertexLabelOverrideAttributeKey(String attributeKey) {
		vertexLabelOverride = attributeKey;
	}

	/**
	 * Returns the attribute key that can override the vertices label text
	 * @return the attribute key that can override the vertices label text
	 */
	public String getVertexLabelOverride() {
		return vertexLabelOverride;
	}

	/**
	 * Sets the attribute key that can be used to override the color for a vertex. Normally, the
	 * color is determined by the vertex type, which will be mapped to a color
	 * @param attributeKey the attribute key that, if set, will be used to define the vertice's color
	 */
	public void setVertexColorOverrideAttributeKey(String attributeKey) {
		vertexColorOverride = attributeKey;
	}

	/**
	 * Sets the attribute key that can be used to override the color for an edge. Normally, the
	 * color is determined by the edge type, which will be mapped to a color
	 * @param attributeKey the attribute key that, if set, will be used to define the edge's color
	 */
	public void setEdgeColorOverrideAttributeKey(String attributeKey) {
		edgeColorOverride = attributeKey;
	}

	/**
	 * Returns the attribute key that can be used to override the color of an edge
	 * @return the attribute key that can be used to override the color of an edge
	 */
	public String getEdgeColorOverrideAttributeKey() {
		return edgeColorOverride;
	}

	/**
	 * Sets the attribute key that can be used to override the shape for a vertex. Normally, the
	 * shape is determined by the vertex type, which will be mapped to a shape
	 * @param attributeKey the attribute key that, if set, will be used to define the vertice's shape
	 */
	public void setVertexShapeOverrideAttributeKey(String attributeKey) {
		vertexShapeOverride = attributeKey;
	}

	/**
	 * Returns the text that will be displayed as the label for the given vertex
	 * @param vertex the vertex for which to get label text
	 * @return the text that will be displayed as the label for the given vertex
	 */
	public String getVertexLabel(AttributedVertex vertex) {
		String vertexLabel = null;

		if (vertexLabelOverride != null) {
			vertexLabel = vertex.getAttribute(vertexLabelOverride);
		}

		if (vertexLabel == null) {
			vertexLabel = vertex.getName();
		}

		if (vertexLabel.contains("\n")) {
			vertexLabel = StringEscapeUtils.escapeHtml4(vertexLabel);
			return "<html>" + String.join("<p>", Splitter.on('\n').split(vertexLabel));
		}
		return vertexLabel;
	}

	/**
	 * Returns the {@link VertexShape} that will be used to draw the vertex's shape
	 * @param vertex the vertex for which to get the shape
	 * @return  the {@link VertexShape} that will be used to draw the vertex's shape
	 */
	public VertexShape getVertexShape(AttributedVertex vertex) {
		if (vertexShapeOverride != null) {
			String shapeName = vertex.getAttribute(vertexShapeOverride);
			if (shapeName != null) {
				VertexShape shape = VertexShape.getShape(shapeName);
				if (shape != null) {
					return shape;
				}
			}
		}
		String vertexType = vertex.getVertexType();
		return vertexShapeMap.getOrDefault(vertexType, defaultVertexShape);
	}

	/**
	 * Returns the color that will be used to draw the vertex
	 * @param vertex the vertex for which to get the color
	 * @return  the color that will be used to draw the vertex
	 */
	public Color getVertexColor(AttributedVertex vertex) {
		if (vertexColorOverride != null) {
			String colorValue = vertex.getAttribute(vertexColorOverride);
			if (colorValue != null) {
				Color color = WebColors.getColor(colorValue);
				if (color != null) {
					return color;
				}
			}
		}

		String vertexType = vertex.getVertexType();
		return vertexColorMap.getOrDefault(vertexType, defaultVertexColor);
	}

	/**
	 * Returns the color that will be used to draw the edge
	 * @param edge the edge for which to get the color
	 * @return  the color that will be used to draw the edge
	 */
	public Color getEdgeColor(AttributedEdge edge) {
		if (edgeColorOverride != null) {
			String colorValue = edge.getAttribute(edgeColorOverride);
			if (colorValue != null) {
				Color color = WebColors.getColor(colorValue);
				if (color != null) {
					return color;
				}
			}
		}

		String edgeType = edge.getEdgeType();
		return edgeColorMap.getOrDefault(edgeType, defaultEdgeColor);
	}

	/**
	 * Returns the priority for the given edge type. This is used by layout algorithms to
	 * determine which edges should have more influence on the layout.
	 * @param edgeType the edge type for which to get it's priority
	 * @return  the priority for the given edge type
	 */
	public Integer getEdgePriority(String edgeType) {
		return edgePriorityMap.getOrDefault(edgeType, Integer.MAX_VALUE);
	}

	/**
	 * Returns the edge type that is the preferred edge for layout purposes
	 * @return the edge type that is the preferred edge for layout purposes
	 */
	public String getFavoredEdgeType() {
		return favoredEdgeType;
	}

	/**
	 * Sets the favored edge type. The favored edge type is used to influence layout algorithms
	 * @param favoredEdgeType the edge type that is to be favored by layout algorithms
	 */
	public void setFavoredEdgeType(String favoredEdgeType) {
		checkEdgeType(favoredEdgeType);
		this.favoredEdgeType = favoredEdgeType;
	}

	/**
	 * Returns the {@link GraphType} that this object provides display options for
	 * @return the {@link GraphType} that this object provides display options for
	 */
	public GraphType getGraphType() {
		return graphType;
	}

	/**
	 * Returns the color for the given vertex type
	 * @param vertexType the vertex type to get the color for
	 * @return the color for the given vertex type
	 */
	public Color getVertexColor(String vertexType) {
		return vertexColorMap.getOrDefault(vertexType, defaultVertexColor);
	}

	/**
	 * Sets the color for vertices with the given vertex type
	 * @param vertexType the vertex type for which to set its color
	 * @param color the color to use for vertices with the given vertex type
	 */
	public void setVertexColor(String vertexType, Color color) {
		checkVertexType(vertexType);
		vertexColorMap.put(vertexType, Objects.requireNonNull(color));
	}

	private String getVertexShapeName(String vertexType) {
		VertexShape vertexShape = vertexShapeMap.getOrDefault(vertexType, defaultVertexShape);
		return vertexShape.getName();
	}

	/**
	 * Sets the {@link VertexShape} to use for vertices with the given vertex type
	 * @param vertexType the vertex type for which to set its shape
	 * @param vertexShape the {@link VertexShape} to use for vertices with the given vertex type
	 */
	public void setVertexShape(String vertexType, VertexShape vertexShape) {
		checkVertexType(vertexType);
		vertexShapeMap.put(vertexType, Objects.requireNonNull(vertexShape));
	}

	/**
	 * Returns the color for the given edge type
	 * @param edgeType the edge type whose color is to be determined.
	 * @return the color for the given edge type.
	 */
	public Color getEdgeColor(String edgeType) {
		return edgeColorMap.getOrDefault(edgeType, defaultEdgeColor);
	}

	/**
	 * Sets the color for edges with the given edge type
	 * @param edgeType the edge type for which to set its color
	 * @param color the new color for edges with the given edge type
	 */
	public void setEdgeColor(String edgeType, Color color) {
		checkEdgeType(edgeType);
		edgeColorMap.put(edgeType, Objects.requireNonNull(color));
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		if (optionName.startsWith(rootOptionsName)) {
			updateOptions(options.getOptions(rootOptionsName));
		}
		notifyListeners();
	}

	/**
	 * Returns the name for the root Options name for this {@link GraphDisplayOptions}
	 * @return the name for the root Options name for this {@link GraphDisplayOptions}
	 */
	public String getRootOptionsName() {
		return rootOptionsName;
	}

	/**
	 * Returns the attribute key that can be used to override the color of a vertex. Normally,
	 * a vertex is colored based on its vertex type. However, if this value is non-null, a vertex
	 * can override its color by setting an attribute using this key name.
	 * @return the attribute key that can be used to override the color of a vertex
	 */
	public String getVertexColorOverrideAttributeKey() {
		return vertexColorOverride;
	}

	/**
	 * Returns the attribute key that can be used to override the shape of a vertex. Normally,
	 * a vertex has a shape based on its vertex type. However, if this value is non-null, a vertex
	 * can override its shape by setting an attribute using this key name.
	 * @return the attribute key that can be used to override the shape of a vertex
	 */
	public String getVertexShapeOverrideAttributeKey() {
		return vertexShapeOverride;
	}

	/**
	 * returns the {@link VertexShape} for any vertex that has not vertex type defined
	 * @return the {@link VertexShape} for any vertex that has not vertex type defined
	 */
	public VertexShape getDefaultVertexShape() {
		return defaultVertexShape;
	}

	/**
	 * Returns the {@link VertexShape} for vertices that have the given vertex type
	 * @param vertexType the vertex type for which to get its asigned shape
	 * @return the {@link VertexShape} for vertices that have the given vertex type
	 */
	public VertexShape getVertexShape(String vertexType) {
		return vertexShapeMap.getOrDefault(vertexType, defaultVertexShape);
	}

	/**
	 * Returns the vertex selection color
	 * @return the vertex selection color
	 */
	public Color getVertexSelectionColor() {
		return vertexSelectionColor;
	}

	/**
	 * Sets the vertex selection color
	 * @param vertexSelectionColor the color to use for highlighting selected vertices
	 */
	public void setVertexSelectionColor(Color vertexSelectionColor) {
		this.vertexSelectionColor = vertexSelectionColor;
	}

	/**
	 * Returns the color for edge selections
	 * @return the color fore edge selections
	 */
	public Color getEdgeSelectionColor() {
		return edgeSelectionColor;
	}

	/**
	 * Sets the edge selection color
	 * @param edgeSelectionColor color to use for highlighting selected edges
	 */
	public void setEdgeSelectionColor(Color edgeSelectionColor) {
		this.edgeSelectionColor = edgeSelectionColor;
	}

	/**
	 * Returns the name of the default graph layout algorithm
	 * @return the name of the default graph layout algorithms
	 */
	public String getDefaultLayoutAlgorithmNameLayout() {
		return defaultLayoutAlgorithmName;
	}

	/**
	 * Sets the name of the default layout algorithm
	 * @param defaultLayout the name of the layout algorithm to use by default
	 */
	public void setDefaultLayoutAlgorithmName(String defaultLayout) {
		this.defaultLayoutAlgorithmName = defaultLayout;
	}

	/**
	 * Returns true if the rendering mode is to use icons for the vertices. If using
	 * icons, the label is drawn inside the shape. 
	 * @return true if the rendering mode is to use icons.
	 */
	public boolean usesIcons() {
		return useIcons;
	}

	/**
	 * Sets whether the graph rendering mode is to use icons or not. If using icons, the label and
	 * shape are drawn together into a cached icon. Otherwise, the shapes are drawn on the fly and
	 * labeled separately.
	 * @param b true to render in icon mode.
	 */
	public void setUsesIcons(boolean b) {
		this.useIcons = b;
	}

	/**
	 * Returns the label position relative to the vertex. Note this is only relevant 
	 * if {@link #usesIcons()} is false
	 * @return  the label position relative to the vertex
	 */
	public GraphLabelPosition getLabelPosition() {
		return labelPosition;
	}

	/**
	 * Sets the label position relative to the vertex. Note this is only relevant
	 * if {@link #usesIcons()} is false.
	 * @param labelPosition the {@link GraphLabelPosition} to use for rendering vertex labels
	 */
	public void setLabelPosition(GraphLabelPosition labelPosition) {
		this.labelPosition = labelPosition;
	}

	/**
	 * Sets the font to use for drawing vertex labels
	 * @param font  the font to use for drawing vertex labels
	 */
	public void setFont(Font font) {
		this.font = font;
	}

	/**
	 * Returns the font being used to render vertex labels
	 * @return the font being used to render vertex labels
	 */
	public Font getFont() {
		return font;
	}

	/**
	 * Returns the length of the arrow. The width will be proportional to the length.
	 * Note: this option is not exposed in the Options because it is too specific to a graph
	 * instance and wouldn't be appropriate to apply to shared options.
	 * @return the size if the arrow
	 */
	public int getArrowLength() {
		return arrowLength;
	}

	/**
	 * Sets the length of the arrow. The width will be proportional to the length.
	 * Note: this option is not exposed in the Options because it is too specific to a graph
	 * instance and wouldn't be appropriate to apply to shared options.
	 * @param length the size of the arrow
	 */
	public void setArrowLength(int length) {
		this.arrowLength = length;
	}

	/**
	 * Returns the maximum number of nodes that can be in a displayed graph
	 * @return the maximum number of nodes that can be in a displayed graph
	 */
	public int getMaxNodeCount() {
		return maxNodeCount;
	}

	/**
	 * Sets the maximum number of nodes a graph can have and still be displayed. Be careful, 
	 * setting this value too high can result in Ghidra running out of memory and/or 
	 * making the system very sluggish.
	 * @param maxNodeCount the maximum number of nodes a graph can have and still be displayed.
	 */
	public void setMaxNodeCount(int maxNodeCount) {
		this.maxNodeCount = maxNodeCount;
	}

	/**
	 * Returns true if this {@link GraphDisplayOptions} instance has been constructed with
	 * a tool for getting/saving option values in the tool options
	 * @return true if this {@link GraphDisplayOptions} instance is connected to tool options
	 */
	public boolean isRegisteredWithTool() {
		return registeredWithTool;
	}

	/**
	 * Registers this GraphTypeDisplayOptions with {@link ToolOptions}. Note: this should only
	 * be used by plugins or other objects that get instantiated immediately when the tool is
	 * constructed. Otherwise, if the tool exits and this hasn't been called, any saved option
	 * values will be lost.
	 * <P>
	 * @param toolOptions the {@link ToolOptions} to register these options with
	 * @param help the help location to be used by the {@link OptionsDialog} for display/editing
	 * these options
	 */
	public void registerOptions(ToolOptions toolOptions, HelpLocation help) {
		Options rootOptions = toolOptions.getOptions(graphType.getOptionsName());
		registerVertexColorOptions(rootOptions, help);
		registerVertexShapeOptions(rootOptions, help);
		registerEdgeColorOptions(rootOptions, help);
		registerMiscellaneousOptions(rootOptions, help);
	}

	/**
	 * Sets default values for vertex types
	 * @param vertexType the vertex type whose default color and shape are being defined
	 * @param vertexShape the default vertex shape for the given vertex type
	 * @param color the default color for the given vertex type
	 */
	protected void configureVertexType(String vertexType, VertexShape vertexShape, Color color) {
		checkVertexType(vertexType);
		vertexShapeMap.put(vertexType, vertexShape);
		vertexColorMap.put(vertexType, color);
	}

	/**
	 * Sets default values for edge types
	 * @param edgeType the edge type whose default color and shape are being defined
	 * @param color the default color for the given edge type
	 */
	protected void configureEdgeType(String edgeType, Color color) {
		checkEdgeType(edgeType);
		edgeColorMap.put(edgeType, color);
	}

	/**
	 * Loads values from tool options
	 * 
	 * @param tool the tool from which to update values.
	 */
	public void initializeFromOptions(Tool tool) {
		if (tool == null) {
			return;
		}
		ToolOptions toolOptions = tool.getOptions("Graph");
		toolOptions.addOptionsChangeListener(this);
		updateOptions(toolOptions.getOptions(rootOptionsName));
		registeredWithTool = true;
	}

	private void updateOptions(Options rootOptions) {
		updateVertexColorsFromOptions(rootOptions);
		updateEdgeColorsFromOptions(rootOptions);
		updateVertexShapesFromOptions(rootOptions);
		updateMiscellaniousOptions(rootOptions);
	}

	private void updateMiscellaniousOptions(Options rootOptions) {
		Options options = rootOptions.getOptions(MISCELLANEOUS_OPTIONS);
		String shapeName = options.getString(DEFAULT_VERTEX_SHAPE, defaultVertexShape.getName());
		defaultVertexShape = VertexShape.getShape(shapeName);

		defaultVertexColor = options.getColor(DEFAULT_VERTEX_COLOR, defaultVertexColor);
		defaultEdgeColor = options.getColor(DEFAULT_EDGE_COLOR, defaultEdgeColor);
		favoredEdgeType = options.getString(FAVORED_EDGE_TYPE, favoredEdgeType);

		vertexSelectionColor = options.getColor(VERTEX_SELECTION_COLOR, vertexSelectionColor);
		edgeSelectionColor = options.getColor(EDGE_SELECTION_COLOR, edgeSelectionColor);

		defaultLayoutAlgorithmName =
			options.getString(DEFAULT_LAYOUT_ALGORITHM, defaultLayoutAlgorithmName);

		useIcons = options.getBoolean(USE_ICONS, useIcons);
		labelPosition = options.getEnum(LABEL_POSITION, labelPosition);
		font = options.getFont(FONT, font);
		maxNodeCount = options.getInt(MAX_NODES_SIZE, maxNodeCount);
	}

	private void updateVertexShapesFromOptions(Options rootOptions) {
		Options options = rootOptions.getOptions(VERTEX_SHAPES);
		for (String vertexType : graphType.getVertexTypes()) {
			String current = getVertexShapeName(vertexType);
			String shapeName = options.getString(vertexType, current);
			if (shapeName != null && !shapeName.equals(current)) {
				VertexShape shape = VertexShape.getShape(shapeName);
				if (shape != null) {
					setVertexShape(vertexType, VertexShape.getShape(shapeName));
				}
			}
		}
	}

	private void updateEdgeColorsFromOptions(Options rootOptions) {
		Options options = rootOptions.getOptions(EDGE_COLORS);
		for (String edgeType : graphType.getEdgeTypes()) {
			Color current = getEdgeColor(edgeType);
			Color color = options.getColor(edgeType, current);
			if (color != null && !color.equals(current)) {
				setEdgeColor(edgeType, color);
			}
		}
	}

	private void notifyListeners() {
		for (ChangeListener changeListener : changeListeners) {
			changeListener.stateChanged(new ChangeEvent(this));
		}
	}

	private void updateVertexColorsFromOptions(Options rootOptions) {
		Options options = rootOptions.getOptions(VERTEX_COLORS);
		for (String vertexType : graphType.getVertexTypes()) {
			Color current = getVertexColor(vertexType);
			Color color = options.getColor(vertexType, current);
			if (color != null && !color.equals(current)) {
				setVertexColor(vertexType, color);
			}
		}
	}

	private void registerVertexColorOptions(Options rootOptions, HelpLocation help) {
		Options options = rootOptions.getOptions(VERTEX_COLORS);

		for (String vertexType : graphType.getVertexTypes()) {
			options.registerOption(vertexType, OptionType.COLOR_TYPE,
				getVertexColor(vertexType), help,
				"Choose the color for this vertex type");
		}
		List<String> list = new ArrayList<>(graphType.getVertexTypes());
		OptionsEditor editor = new ScrollableOptionsEditor(VERTEX_COLORS, list);
		options.registerOptionsEditor(editor);
	}

	private void registerVertexShapeOptions(Options rootOptions, HelpLocation help) {
		Options options = rootOptions.getOptions(VERTEX_SHAPES);

		List<String> shapeNames = VertexShape.getShapeNames();

		for (String vertexType : graphType.getVertexTypes()) {
			StringWithChoicesEditor editor = new StringWithChoicesEditor(shapeNames);
			options.registerOption(vertexType, OptionType.STRING_TYPE,
				getVertexShapeName(vertexType), help,
				"Choose the shape for this vertex type", editor);
		}
		List<String> list = new ArrayList<>(graphType.getVertexTypes());
		OptionsEditor editor = new ScrollableOptionsEditor(VERTEX_SHAPES, list);
		options.registerOptionsEditor(editor);
	}

	private void registerEdgeColorOptions(Options rootOptions, HelpLocation help) {
		Options options = rootOptions.getOptions(EDGE_COLORS);

		for (String edgeType : graphType.getEdgeTypes()) {
			options.registerOption(edgeType, OptionType.COLOR_TYPE,
				getEdgeColor(edgeType), help, "Choose the color for this edge type");
		}
		List<String> list = new ArrayList<>(graphType.getEdgeTypes());
		OptionsEditor editor = new ScrollableOptionsEditor(EDGE_COLORS, list);
		options.registerOptionsEditor(editor);
	}

	private void registerMiscellaneousOptions(Options rootOptions, HelpLocation help) {

		Options options = rootOptions.getOptions(MISCELLANEOUS_OPTIONS);

		options.registerOption(MAX_NODES_SIZE, OptionType.INT_TYPE, maxNodeCount, help,
			"Graphs with more than this number of nodes will not be displayed. (Large graphs can cause Ghidra to become unstable/sluggish)");
		StringWithChoicesEditor editor = new StringWithChoicesEditor(VertexShape.getShapeNames());

		options.registerOption(VERTEX_SELECTION_COLOR, OptionType.COLOR_TYPE, vertexSelectionColor,
			help, "Color for highlighting selected vertices");

		options.registerOption(EDGE_SELECTION_COLOR, OptionType.COLOR_TYPE, edgeSelectionColor,
			help, "Color for highlighting selected edge");

		options.registerOption(DEFAULT_VERTEX_SHAPE, OptionType.STRING_TYPE,
			defaultVertexShape.getName(),
			help, "Shape for vertices that have no vertex type defined", editor);

		options.registerOption(DEFAULT_VERTEX_COLOR, OptionType.COLOR_TYPE, defaultVertexColor,
			help, "Color for vertices that have no vertex type defined");

		options.registerOption(DEFAULT_EDGE_COLOR, OptionType.COLOR_TYPE, defaultEdgeColor,
			help, "Color for edge that have no edge type defined");

		List<String> edgeTypes = graphType.getEdgeTypes();
		if (!edgeTypes.isEmpty()) {
			editor = new StringWithChoicesEditor(edgeTypes);
			options.registerOption(FAVORED_EDGE_TYPE, OptionType.STRING_TYPE, favoredEdgeType, help,
				"Favored edge is used to influence layout algorithms", editor);
		}

		editor = new StringWithChoicesEditor(LayoutAlgorithmNames.getLayoutAlgorithmNames());
		options.registerOption(DEFAULT_LAYOUT_ALGORITHM, OptionType.STRING_TYPE,
			defaultLayoutAlgorithmName, help, "Initial layout algorithm", editor);

		options.registerOption(USE_ICONS, OptionType.BOOLEAN_TYPE, useIcons, help,
			"If true, vertices are drawn using pre-rendered images versus compact shapes");

		options.registerOption(LABEL_POSITION, OptionType.ENUM_TYPE, labelPosition, help,
			"Relative postion of labels to vertex shape (Only applicable if \"Use Icons\" is true");

		options.registerOption(FONT, OptionType.FONT_TYPE, font, help,
			"Font to use for vertex labels");

		List<String> optionNamesInDisplayOrder = new ArrayList<>();

		optionNamesInDisplayOrder.add(MAX_NODES_SIZE);
		optionNamesInDisplayOrder.add(VERTEX_SELECTION_COLOR);
		optionNamesInDisplayOrder.add(EDGE_SELECTION_COLOR);
		optionNamesInDisplayOrder.add(DEFAULT_VERTEX_COLOR);
		optionNamesInDisplayOrder.add(DEFAULT_EDGE_COLOR);
		optionNamesInDisplayOrder.add(DEFAULT_VERTEX_SHAPE);
		optionNamesInDisplayOrder.add(FAVORED_EDGE_TYPE);
		optionNamesInDisplayOrder.add(DEFAULT_LAYOUT_ALGORITHM);
		optionNamesInDisplayOrder.add(LABEL_POSITION);
		optionNamesInDisplayOrder.add(FONT);
		optionNamesInDisplayOrder.add(USE_ICONS);

		OptionsEditor optionsEditor =
			new ScrollableOptionsEditor(MISCELLANEOUS_OPTIONS, optionNamesInDisplayOrder);
		options.registerOptionsEditor(optionsEditor);

	}

	private void checkVertexType(String vertexType) {
		if (!getGraphType().containsVertexType(vertexType)) {
			throw new IllegalArgumentException("VertexType \"" + vertexType +
				"\" not defined in GraphType \"" + getGraphType().getName() + "\".");
		}
	}

	private void checkEdgeType(String edgeType) {
		if (!getGraphType().containsEdgeType(edgeType)) {
			throw new IllegalArgumentException("EdgeType \"" + edgeType +
				"\" not defined in GraphType \"" + getGraphType().getName() + "\".");
		}
	}

}
