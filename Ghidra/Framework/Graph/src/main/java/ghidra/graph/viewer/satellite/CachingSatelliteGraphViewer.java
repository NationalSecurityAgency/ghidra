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
package ghidra.graph.viewer.satellite;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.layout.ObservableCachingLayout;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import edu.uci.ics.jung.visualization.transform.shape.ShapeTransformer;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer;
import ghidra.util.task.SwingUpdateManager;

public class CachingSatelliteGraphViewer<V extends VisualVertex, E extends VisualEdge<V>>
		extends SatelliteGraphViewer<V, E> {

	private BufferedImage bufferedBackgroundImage = null;
	private BufferedImage bufferedOverlayImage = null;

	private Color backgroundColor;

	private VisualVertexSatelliteRenderer<V, E> highlightRenderer =
		new VisualVertexSatelliteRenderer<>();

	private SwingUpdateManager satelliteUpdateManager = new SwingUpdateManager(750, () -> {
		clearCache();
		VisualGraphViewUpdater<V, E> updater = graphViewer.getViewUpdater();
		updater.fitGraphToViewerLater(CachingSatelliteGraphViewer.this);
		repaint();
	});

	public CachingSatelliteGraphViewer(GraphViewer<V, E> masterViewer, Dimension preferredSize) {
		super(masterViewer, preferredSize);

		preRenderers.clear(); // remove default lens painter

		// same behavior as default ViewLens
		backgroundColor = masterViewer.getBackground().darker();
		setBackground(backgroundColor);

		Layout<V, E> layout = masterViewer.getGraphLayout();
		if (layout instanceof ObservableCachingLayout<?, ?>) {
			ObservableCachingLayout<?, ?> cachingLayout = (ObservableCachingLayout<?, ?>) layout;
			cachingLayout.addChangeListener(e -> satelliteUpdateManager.updateNow());
		}
	}

	// Overridden to update our cache when our size changes, as our layout is based upon our size
	@Override
	public void setBounds(int x, int y, int width, int height) {
		clearCache();
		super.setBounds(x, y, width, height);
	}

	@Override
	public Renderer.Vertex<V, E> getPreferredVertexRenderer() {
		return new VisualVertexSatelliteRenderer<V, E>() {
			@Override
			protected void paintHighlight(RenderContext<V, E> rc, V vertex, GraphicsDecorator g,
					Rectangle bounds) {
				// Stub--we don't want the render to paint highlights, as we use a static,
				// cached image.  We will manually paint highlights in the paint routine of this
				// viewer.
			}
		};
	}

	private void clearCache() {
		bufferedBackgroundImage = null;
		bufferedOverlayImage = null;
	}

	private void refreshBufferedImageAsNeeded(Graphics g) {
		if (bufferedBackgroundImage != null && bufferedOverlayImage != null) {
			return;
		}

		bufferedBackgroundImage =
			new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_INT_ARGB);
		Graphics2D graphics = (Graphics2D) bufferedBackgroundImage.getGraphics();
		setBackground(backgroundColor);
		renderGraph(graphics);
		graphics.dispose();

		bufferedOverlayImage =
			new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_INT_ARGB);
		graphics = (Graphics2D) bufferedOverlayImage.getGraphics();
		setBackground(Color.WHITE);
		renderGraph(graphics);
		setBackground(backgroundColor);
		graphics.dispose();
	}

	// overridden to use our buffered image in order to speed up painting
	@Override
	protected void paintComponent(Graphics g) {
//		super.paintComponent(g);

//      Original Code - We don't have a need to support double buffering, I think...so don't do it
//
//		Graphics2D g2d = (Graphics2D)g;
//		if(doubleBuffered) {
//		    checkOffscreenImage(getSize());
//			renderGraph(offscreenG2d);
//		    g2d.drawImage(offscreen, null, 0, 0);
//		} else {
//		    renderGraph(g2d);
//		}

		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHints(renderingHints);

		refreshBufferedImageAsNeeded(g);

		g.drawImage(bufferedBackgroundImage, 0, 0, null);

		MultiLayerTransformer myMultiLayerTransformer = renderContext.getMultiLayerTransformer();
		ShapeTransformer masterViewTransformer =
			master.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.VIEW);
		ShapeTransformer masterLayoutTransformer =
			master.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.LAYOUT);
		ShapeTransformer vvLayoutTransformer = myMultiLayerTransformer.getTransformer(Layer.LAYOUT);

		Shape lens = master.getBounds();

		lens = masterViewTransformer.inverseTransform(lens);
		lens = masterLayoutTransformer.inverseTransform(lens);
		lens = vvLayoutTransformer.transform(lens);

		Shape lensClip = master.getBounds();
		lensClip = myMultiLayerTransformer.getTransformer(Layer.VIEW).transform(lens);

		Shape originalClip = g2d.getClip();
		Rectangle clip = lensClip.getBounds();
		g2d.setClip(clip);
		g2d.drawImage(bufferedOverlayImage, 0, 0, null);
		g2d.setClip(originalClip);

		paintSelectedVertices(g2d);
	}

	private void paintSelectedVertices(Graphics2D g2d) {
		GraphicsDecorator graphicsContext = renderContext.getGraphicsContext();
		if (graphicsContext == null) {
			return;
		}

		Layout<V, E> layout = model.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();

		Collection<V> vertices = graph.getVertices();
		List<V> selectedVertices = new LinkedList<>();
		for (V vertex : vertices) {
			if (vertex.isSelected()) {
				selectedVertices.add(vertex);
			}
		}

		graphicsContext.setDelegate(g2d);

		AffineTransform oldXform = g2d.getTransform();
		AffineTransform newXform = new AffineTransform(oldXform);
		newXform.concatenate(
			renderContext.getMultiLayerTransformer().getTransformer(Layer.VIEW).getTransform());
		g2d.setTransform(newXform);

		for (V vertex : selectedVertices) {
			highlightRenderer.paintVertex(renderContext, layout, vertex);
		}

		g2d.setTransform(oldXform);
	}
}
