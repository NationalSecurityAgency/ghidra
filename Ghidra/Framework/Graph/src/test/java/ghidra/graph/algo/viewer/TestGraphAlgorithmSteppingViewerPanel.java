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
package ghidra.graph.algo.viewer;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import edu.uci.ics.jung.visualization.decorators.EdgeShape;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import generic.util.image.ImageUtils;
import ghidra.graph.*;
import ghidra.graph.algo.GraphAlgorithmStatusListener;
import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.graph.viewer.vertex.VisualVertexRenderer;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;

public class TestGraphAlgorithmSteppingViewerPanel<V, E extends GEdge<V>> extends JPanel {

	private GraphViewer<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> viewer;
	private GDirectedGraph<V, E> graph;
	private BidiMap<V, AlgorithmTestSteppingVertex<V>> vertexLookupMap = new DualHashBidiMap<>();

	private List<BufferedImage> images = new ArrayList<>();
	private JPanel phasesPanel;
	private float zoom = .5f;
	private SwingUpdateManager zoomRebuilder = new SwingUpdateManager(() -> rebuildImages());

	private JPanel buttonPanel;
	private AlgorithmSteppingTaskMonitor steppingMonitor;
	private AbstractButton nextButton;
	private GraphAlgorithmStatusListener<V> algorithmStatusListener =
		new GraphAlgorithmStatusListener<>() {

			public void finished() {
				nextButton.setEnabled(true);
				nextButton.setText("Done");
			}

			public void statusChanged(V v, STATUS s) {

				totalStatusChanges++;

				AlgorithmTestSteppingVertex<V> vv = vertexLookupMap.get(v);
				vv.setStatus(s);
				repaint();

				addCurrentGraphToPhases();
			}

			private void addCurrentGraphToPhases() {

				Rectangle layoutShape = GraphViewerUtils.getTotalGraphSizeInLayoutSpace(viewer);
				Rectangle viewShape = GraphViewerUtils.translateRectangleFromLayoutSpaceToViewSpace(
					viewer, layoutShape);

				int w = viewShape.x + viewShape.width;
				int h = viewShape.y + viewShape.height;

				BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
				Graphics2D g = (Graphics2D) image.getGraphics();
				g.setColor(Color.WHITE);
				g.fillRect(0, 0, w, h);

				try {
					SwingUtilities.invokeAndWait(() -> {
						viewer.paint(g);
					});
				}
				catch (Exception e) {
					Msg.debug(this, "Unexpected exception", e);
				}

				images.add(image);
				zoomRebuilder.updateLater();
			}
		};

	public TestGraphAlgorithmSteppingViewerPanel(GDirectedGraph<V, E> graph,
			AlgorithmSteppingTaskMonitor steppingMonitor) {
		this.graph = graph;
		this.steppingMonitor = steppingMonitor;

		buildGraphViewer();
		buildPhasesViewer();
		buildButtons();

		setLayout(new BorderLayout());
		add(viewer, BorderLayout.CENTER);
		add(buttonPanel, BorderLayout.SOUTH);

		steppingMonitor.addStepListener(() -> {
			repaint();
			nextButton.setEnabled(true);
		});
	}

	public GraphAlgorithmStatusListener<V> getStatusListener() {
		return algorithmStatusListener;
	}

	private void buildGraphViewer() {
		TestGraph tvg = new TestGraph();

		Collection<V> vertices = graph.getVertices();
		for (V v : vertices) {
			AlgorithmTestSteppingVertex<V> newV = new AlgorithmTestSteppingVertex<>(v);
			tvg.addVertex(newV);
			vertexLookupMap.put(v, newV);
		}

		Collection<E> edges = graph.getEdges();
		for (E e : edges) {
			V start = e.getStart();
			V end = e.getEnd();
			AlgorithmTestSteppingVertex<V> newStart = vertexLookupMap.get(start);
			AlgorithmTestSteppingVertex<V> newEnd = vertexLookupMap.get(end);
			AlgorithmTestSteppingEdge<V> newEdge =
				new AlgorithmTestSteppingEdge<>(newStart, newEnd);
			tvg.addEdge(newEdge);
		}

		TestGraphLayout layout = new TestGraphLayout(tvg);

		tvg.setLayout(layout);
		viewer = new GraphViewer<>(layout, new Dimension(400, 400));
		viewer.setGraphOptions(new VisualGraphOptions());

		Renderer<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> renderer =
			viewer.getRenderer();

		// TODO set renderer directly
		renderer.setVertexRenderer(new VisualVertexRenderer<>());

		// TODO note: this is needed to 1) use shapes and 2) center the vertices
		VisualGraphVertexShapeTransformer<AlgorithmTestSteppingVertex<V>> shaper =
			new VisualGraphVertexShapeTransformer<>();
		viewer.getRenderContext().setVertexShapeTransformer(shaper);

		viewer.getRenderContext().setEdgeShapeTransformer(EdgeShape.line(tvg));

		viewer.getRenderContext().setVertexLabelTransformer(v -> v.toString());
	}

	private void buildPhasesViewer() {
		JFrame f = new JFrame("Graph Phases");
		JPanel parentPanel = new JPanel(new BorderLayout());
		phasesPanel = new JPanel();

		JPanel zoomPanel = new JPanel();
		JButton inButton = new JButton("+");
		inButton.addActionListener(e -> {
			float newZoom = zoom + .1f;
			zoom = Math.min(1f, newZoom);
			zoomRebuilder.update();
		});
		JButton outButton = new JButton("-");
		outButton.addActionListener(e -> {
			float newZoom = zoom - .1f;
			zoom = Math.max(0.1f, newZoom);
			zoomRebuilder.update();
		});
		zoomPanel.add(inButton);
		zoomPanel.add(outButton);

		parentPanel.add(phasesPanel, BorderLayout.CENTER);
		parentPanel.add(zoomPanel, BorderLayout.SOUTH);

		f.getContentPane().add(parentPanel);

		f.setSize(400, 400);
		f.setVisible(true);
	}

	private void rebuildImages() {

		phasesPanel.removeAll();

		double scale = zoom;

		images.forEach(image -> {

			int w = image.getWidth();
			int h = image.getHeight();
			double sw = w * scale;
			double sh = h * scale;
			Image scaledImage =
				ImageUtils.createScaledImage(image, (int) sw, (int) sh, Image.SCALE_AREA_AVERAGING);
			JLabel label = new JLabel(new ImageIcon(scaledImage));
			phasesPanel.add(label);
		});

		phasesPanel.invalidate();
		phasesPanel.getParent().revalidate();
		phasesPanel.repaint();
	}

	private void buildButtons() {
		buttonPanel = new JPanel();

		nextButton = new JButton("Next >>");
		nextButton.addActionListener(e -> {
			nextButton.setEnabled(false);
			steppingMonitor.step();
		});
		nextButton.setEnabled(false);

		buttonPanel.add(nextButton);
	}

	private class TestGraph extends
			DefaultVisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> {

		private TestGraphLayout layout;

		@Override
		public TestGraphLayout getLayout() {
			return layout;
		}

		public void setLayout(TestGraphLayout layout) {
			this.layout = layout;
		}

		@Override
		public TestGraph copy() {

			TestGraph newGraph = new TestGraph();

			Collection<AlgorithmTestSteppingVertex<V>> myVertices = getVertices();
			for (AlgorithmTestSteppingVertex<V> v : myVertices) {
				newGraph.addVertex(v);
			}

			Collection<AlgorithmTestSteppingEdge<V>> myEdges = getEdges();
			for (AlgorithmTestSteppingEdge<V> e : myEdges) {
				newGraph.addEdge(e);
			}

			return newGraph;
		}
	}

	private class TestGraphLayout extends
			AbstractVisualGraphLayout<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> {

		protected TestGraphLayout(TestGraph graph) {
			super(graph, "Test Layout");
		}

		@SuppressWarnings("unchecked")
		@Override
		public VisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> getVisualGraph() {
			return (VisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>>) getGraph();
		}

		@Override
		protected boolean isCondensedLayout() {
			return false;
		}

		@Override
		protected GridLocationMap<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> performInitialGridLayout(
				VisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> g)
				throws CancelledException {

			GridLocationMap<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> grid =
				new GridLocationMap<>();

			// sort by name; assume name is just a number
			List<AlgorithmTestSteppingVertex<V>> sorted = new ArrayList<>(g.getVertices());
			Collections.sort(sorted, (v1, v2) -> {
				Integer i1 = Integer.parseInt(v1.getName());
				Integer i2 = Integer.parseInt(v2.getName());
				return i1.compareTo(i2);
			});

			AlgorithmTestSteppingVertex<V> first = sorted.get(0);
			assignRows(first, g, grid, 1, 1);

			return grid;
		}

		private void assignRows(AlgorithmTestSteppingVertex<V> v,
				VisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> g,
				GridLocationMap<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> grid,
				int row, int col) {

			int existing = grid.row(v);
			if (existing > 0) {
				return; // already processed
			}

			grid.row(v, row);
			grid.col(v, col);
			int nextRow = row++;

			Collection<AlgorithmTestSteppingEdge<V>> children = g.getOutEdges(v);
			int n = children.size();
			int middle = n / 2;
			int start = col - middle;
			int childCol = start;

			for (AlgorithmTestSteppingEdge<V> edge : children) {
				AlgorithmTestSteppingVertex<V> child = edge.getEnd();
				assignRows(child, g, grid, nextRow + 1, childCol++);
			}
		}

		@Override
		public AbstractVisualGraphLayout<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> createClonedLayout(
				VisualGraph<AlgorithmTestSteppingVertex<V>, AlgorithmTestSteppingEdge<V>> newGraph) {

			TestGraphLayout newLayout = new TestGraphLayout((TestGraph) newGraph);
			return newLayout;
		}

	}
}
