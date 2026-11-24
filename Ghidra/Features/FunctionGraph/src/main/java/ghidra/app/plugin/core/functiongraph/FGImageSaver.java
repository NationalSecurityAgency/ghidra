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
package ghidra.app.plugin.core.functiongraph;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.swing.JComponent;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.renderers.Renderer.Edge;
import edu.uci.ics.jung.visualization.renderers.Renderer.Vertex;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import generic.util.image.ImageUtils;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.FGEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.FGVertexRenderer;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGView;
import ghidra.graph.viewer.*;
import ghidra.util.filechooser.ExtensionFileFilter;

class FGImageSaver {

	private FGView view;

	FGImageSaver(FGView view) {
		this.view = view;
	}

	private File getSaveFile() {

		GhidraFileChooser chooser = new GhidraFileChooser(view.getViewComponent());
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle("Save Image");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileFilter(ExtensionFileFilter.forExtensions("PNG Files", "png"));
		chooser.setLastDirectoryPreference("FunctionGraphSaveImageDir");
		File file = chooser.getSelectedFile();
		if (file == null) {
			return null; // cancelled
		}

		return validateImageFile(file);
	}

	boolean saveGraphViewToImage() throws IOException {

		File saveFile = getSaveFile();
		if (saveFile == null) {
			return false; // cancelled
		}

		JComponent component = view.getViewComponent();
		Image graphImage = ImageUtils.createImage(component);
		ImageUtils.writeFile(graphImage, saveFile);
		return true;
	}

	boolean saveFullGraphToImage() throws IOException {

		File saveFile = getSaveFile();
		if (saveFile == null) {
			return false; // cancelled
		}

		GraphComponent<FGVertex, FGEdge, FunctionGraph> graphComponent =
			view.getGraphComponent();
		GraphViewer<FGVertex, FGEdge> viewer = graphComponent.getPrimaryViewer();
		Rectangle layoutBounds = GraphViewerUtils.getTotalGraphSizeInLayoutSpace(viewer);
		Rectangle fullBounds = new Rectangle(0, 0, layoutBounds.width, layoutBounds.height);

		// add some padding
		int padding = 40;
		fullBounds.x -= padding;
		fullBounds.y -= padding;
		fullBounds.width += (2 * padding);
		fullBounds.height += (2 * padding);

		BufferedImage bi =
			new BufferedImage(fullBounds.width, fullBounds.height, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2d = bi.createGraphics();

		GraphPerspectiveInfo<FGVertex, FGEdge> oldPerspective = view.generateGraphPerspective();
		Renderer<FGVertex, FGEdge> graphRenderer = viewer.getRenderer();
		Vertex<FGVertex, FGEdge> oldVertexRenderer = graphRenderer.getVertexRenderer();
		Edge<FGVertex, FGEdge> oldEdgeRenderer = graphRenderer.getEdgeRenderer();

		RenderContext<FGVertex, FGEdge> rc = viewer.getRenderContext();
		MultiLayerTransformer mxform = rc.getMultiLayerTransformer();
		MutableTransformer lxform = mxform.getTransformer(Layer.LAYOUT);
		MutableTransformer vxform = mxform.getTransformer(Layer.VIEW);

		FullVertexRenderer fullVertexRenderer = new FullVertexRenderer();
		FullEdgeRenderer fullEdgeRenderer = new FullEdgeRenderer();
		graphRenderer.setVertexRenderer(fullVertexRenderer);
		graphRenderer.setEdgeRenderer(fullEdgeRenderer);

		try {
			lxform.setTranslate(0, 0);
			vxform.setTranslate(0, 0);
			vxform.setScale(1.0, 1.0, new Point(0, 0));

			g2d.setColor(viewer.getBackground());
			g2d.fillRect(0, 0, fullBounds.width, fullBounds.height);

			viewer.renderGraph(g2d);
			g2d.dispose();
		}
		finally {

			graphRenderer.setVertexRenderer(oldVertexRenderer);
			graphRenderer.setEdgeRenderer(oldEdgeRenderer);
			view.setGraphPerspective(oldPerspective);

		}

		ImageUtils.writeFile((Image) bi, saveFile);
		return true;
	}

	private File validateImageFile(File file) {

		String name = file.getName();
		if (!name.endsWith(".png")) {
			File parent = file.getParentFile();
			file = new File(parent, name + ".png");
		}

		if (file.exists()) {
			int choice =
				OptionDialog.showOptionDialogWithCancelAsDefaultButton(view.getViewComponent(),
					"Overwrite?", "File exists.  Overwrite?", "Overwrite");
			if (choice == OptionDialog.CANCEL_OPTION) {
				return null;
			}
		}

		return file;
	}

	private class FullVertexRenderer extends FGVertexRenderer {

		@Override
		protected boolean vertexHit(RenderContext<FGVertex, FGEdge> rc, Shape s) {
			return true;
		}
	}

	private class FullEdgeRenderer extends FGEdgeRenderer {
		@Override
		protected boolean shapeHit(RenderContext<FGVertex, FGEdge> rc, Shape s) {
			return true;
		}
	}

}
