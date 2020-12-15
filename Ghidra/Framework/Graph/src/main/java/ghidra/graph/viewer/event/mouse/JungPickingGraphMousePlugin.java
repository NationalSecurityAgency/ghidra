/* ###
 * IP: BSD
 */
/*
 * Copyright (c) 2005, The JUNG Authors 
 *
 * All rights reserved.
 *
 * This software is open-source under the BSD license; see either
 * "license.txt" or
 * https://github.com/jrtom/jung/blob/master/LICENSE for a description.
 * Created on Mar 8, 2005
 *
 */
package ghidra.graph.viewer.event.mouse;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.Collection;

import javax.swing.JComponent;

import edu.uci.ics.jung.algorithms.layout.GraphElementAccessor;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.Layer;
import edu.uci.ics.jung.visualization.VisualizationServer.Paintable;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import edu.uci.ics.jung.visualization.picking.PickedState;

/** 
 * PickingGraphMousePlugin supports the picking of graph elements
 * with the mouse. MouseButtonOne picks a single vertex
 * or edge, and MouseButtonTwo adds to the set of selected Vertices
 * or EdgeType. If a Vertex is selected and the mouse is dragged while
 * on the selected Vertex, then that Vertex will be repositioned to
 * follow the mouse until the button is released.
 * 
 * @author Tom Nelson
 * 
 * 
 * Note: this class was copied completely from Jung 2.   Minimal changes were applied to get
 * correct mouse behavior by using {@link MouseEvent#getModifiersEx()}.
 * @param <V> the vertex type
 * @param <E> the edge type
 * 
 */
public class JungPickingGraphMousePlugin<V, E> extends AbstractGraphMousePlugin
		implements MouseListener, MouseMotionListener {

	/**
	 * the picked Vertex, if any
	 */
	protected V vertex;

	/**
	 * the picked Edge, if any
	 */
	protected E edge;

	/**
	 * the x distance from the picked vertex center to the mouse point
	 */
	protected double offsetx;

	/**
	 * the y distance from the picked vertex center to the mouse point
	 */
	protected double offsety;

	/**
	 * controls whether the Vertices may be moved with the mouse
	 */
	protected boolean locked;

	/**
	 * additional modifiers for the action of adding to an existing
	 * selection
	 */
	protected int addToSelectionModifiers;

	/**
	 * used to draw a rectangle to contain picked vertices
	 */
	protected Rectangle2D rect = new Rectangle2D.Float();

	/**
	 * the Paintable for the lens picking rectangle
	 */
	protected Paintable lensPaintable;

	/**
	 * color for the picking rectangle
	 */
	protected Color lensColor = Color.cyan;

	/**
	 * create an instance with default settings
	 */
	public JungPickingGraphMousePlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK,
			InputEvent.BUTTON1_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
	}

	/**
	 * create an instance with overrides
	 * @param selectionModifiers for primary selection
	 * @param addToSelectionModifiers for additional selection
	 */
	public JungPickingGraphMousePlugin(int selectionModifiers, int addToSelectionModifiers) {
		super(selectionModifiers);
		this.addToSelectionModifiers = addToSelectionModifiers;
		this.lensPaintable = new LensPaintable();
		this.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
	}

	/**
	 * @return Returns the lensColor.
	 */
	public Color getLensColor() {
		return lensColor;
	}

	/**
	 * @param lensColor The lensColor to set.
	 */
	public void setLensColor(Color lensColor) {
		this.lensColor = lensColor;
	}

	/**
	 * a Paintable to draw the rectangle used to pick multiple
	 * Vertices
	 * @author Tom Nelson
	 *
	 */
	class LensPaintable implements Paintable {

		@Override
		public void paint(Graphics g) {
			Color oldColor = g.getColor();
			g.setColor(lensColor);
			((Graphics2D) g).draw(rect);
			g.setColor(oldColor);
		}

		@Override
		public boolean useTransform() {
			return false;
		}
	}

	/**
	 * For primary modifiers (default, MouseButton1):
	 * pick a single Vertex or Edge that
	 * is under the mouse pointer. If no Vertex or edge is under
	 * the pointer, unselect all picked Vertices and edges, and
	 * set up to draw a rectangle for multiple selection
	 * of contained Vertices.
	 * For additional selection (default Shift+MouseButton1):
	 * Add to the selection, a single Vertex or Edge that is
	 * under the mouse pointer. If a previously picked Vertex
	 * or Edge is under the pointer, it is un-picked.
	 * If no vertex or Edge is under the pointer, set up
	 * to draw a multiple selection rectangle (as above)
	 * but do not unpick previously picked elements.
	 * 
	 * @param e the event
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void mousePressed(MouseEvent e) {
		down = e.getPoint();
		VisualizationViewer<V, E> vv = (VisualizationViewer<V, E>) e.getSource();
		GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
		PickedState<V> pickedVertexState = vv.getPickedVertexState();
		PickedState<E> pickedEdgeState = vv.getPickedEdgeState();
		if (pickSupport != null && pickedVertexState != null) {
			Layout<V, E> layout = vv.getGraphLayout();
			if (e.getModifiersEx() == modifiers) {
				rect.setFrameFromDiagonal(down, down);
				// p is the screen point for the mouse event
				Point2D ip = e.getPoint();

				vertex = pickSupport.getVertex(layout, ip.getX(), ip.getY());
				if (vertex != null) {
					if (pickedVertexState.isPicked(vertex) == false) {
						pickedVertexState.clear();
						pickedVertexState.pick(vertex, true);
					}
					// layout.getLocation applies the layout Function so
					// q is transformed by the layout Function only
					Point2D q = layout.apply(vertex);
					// transform the mouse point to graph coordinate system
					Point2D gp = vv.getRenderContext()
							.getMultiLayerTransformer()
							.inverseTransform(Layer.LAYOUT, ip);

					offsetx = (float) (gp.getX() - q.getX());
					offsety = (float) (gp.getY() - q.getY());
				}
				else if ((edge = pickSupport.getEdge(layout, ip.getX(), ip.getY())) != null) {
					pickedEdgeState.clear();
					pickedEdgeState.pick(edge, true);
				}
				else {
					vv.addPostRenderPaintable(lensPaintable);
					pickedEdgeState.clear();
					pickedVertexState.clear();
				}

			}
			else if (e.getModifiersEx() == addToSelectionModifiers) {
				vv.addPostRenderPaintable(lensPaintable);
				rect.setFrameFromDiagonal(down, down);
				Point2D ip = e.getPoint();
				vertex = pickSupport.getVertex(layout, ip.getX(), ip.getY());
				if (vertex != null) {
					boolean wasThere =
						pickedVertexState.pick(vertex, !pickedVertexState.isPicked(vertex));
					if (wasThere) {
						vertex = null;
					}
					else {

						// layout.getLocation applies the layout Function so
						// q is transformed by the layout Function only
						Point2D q = layout.apply(vertex);
						// translate mouse point to graph coord system
						Point2D gp = vv.getRenderContext()
								.getMultiLayerTransformer()
								.inverseTransform(Layer.LAYOUT, ip);

						offsetx = (float) (gp.getX() - q.getX());
						offsety = (float) (gp.getY() - q.getY());
					}
				}
				else if ((edge = pickSupport.getEdge(layout, ip.getX(), ip.getY())) != null) {
					pickedEdgeState.pick(edge, !pickedEdgeState.isPicked(edge));
				}
			}
		}
		if (vertex != null) {
			e.consume();
		}
	}

	/**
	 * If the mouse is dragging a rectangle, pick the
	 * Vertices contained in that rectangle
	 * 
	 * clean up settings from mousePressed
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void mouseReleased(MouseEvent e) {
		VisualizationViewer<V, E> vv = (VisualizationViewer<V, E>) e.getSource();
		if (e.getModifiersEx() == this.addToSelectionModifiers) {
			if (down != null) {
				Point2D out = e.getPoint();

				if (vertex == null && heyThatsTooClose(down, out, 5) == false) {
					pickContainedVertices(vv, down, out, false);
				}
			}
		}
		else {

			// Mouse released without the 'add to selection' modifiers. See if we have been dragging
			if (down != null) {
				// check to see if we were dragging (no vertex picked and a large enough rectangle)
				Point2D out = e.getPoint();
				if (vertex == null && heyThatsTooClose(down, out, 5) == false) {
					pickContainedVertices(vv, down, out, true);
				}
			}

		}

		down = null;
		vertex = null;
		edge = null;
		rect.setFrame(0, 0, 0, 0);
		vv.removePostRenderPaintable(lensPaintable);
		vv.repaint();
	}

	/**
	 * If the mouse is over a picked vertex, drag all picked
	 * vertices with the mouse.
	 * If the mouse is not over a Vertex, draw the rectangle
	 * to select multiple Vertices
	 * 
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void mouseDragged(MouseEvent e) {
		if (locked == false) {
			VisualizationViewer<V, E> vv = (VisualizationViewer<V, E>) e.getSource();
			if (vertex != null) {
				Point p = e.getPoint();
				Point2D graphPoint =
					vv.getRenderContext().getMultiLayerTransformer().inverseTransform(p);
				Point2D graphDown =
					vv.getRenderContext().getMultiLayerTransformer().inverseTransform(down);
				Layout<V, E> layout = vv.getGraphLayout();
				double dx = graphPoint.getX() - graphDown.getX();
				double dy = graphPoint.getY() - graphDown.getY();
				PickedState<V> ps = vv.getPickedVertexState();

				for (V v : ps.getPicked()) {
					Point2D vp = layout.apply(v);
					vp.setLocation(vp.getX() + dx, vp.getY() + dy);
					layout.setLocation(v, vp);
				}
				down = p;

			}
			else {
				Point2D out = e.getPoint();
				if (e.getModifiersEx() == this.addToSelectionModifiers ||
					e.getModifiersEx() == modifiers) {
					rect.setFrameFromDiagonal(down, out);
				}
			}
			if (vertex != null) {
				e.consume();
			}
			vv.repaint();
		}
	}

	private boolean heyThatsTooClose(Point2D p, Point2D q, double min) {
		return Math.abs(p.getX() - q.getX()) < min &&
			Math.abs(p.getY() - q.getY()) < min;
	}

	/**
	 * pick the vertices inside the rectangle created from points 'down' and 'out' (two diagonally
	 * opposed corners of the rectangle)
	 * 
	 * @param vv the viewer containing the layout and picked state
	 * @param down one corner of the rectangle
	 * @param out the other corner of the rectangle
	 * @param clear whether to reset existing picked state
	 */
	protected void pickContainedVertices(VisualizationViewer<V, E> vv, Point2D down, Point2D out,
			boolean clear) {

		Layout<V, E> layout = vv.getGraphLayout();
		PickedState<V> pickedVertexState = vv.getPickedVertexState();

		Rectangle2D pickRectangle = new Rectangle2D.Double();
		pickRectangle.setFrameFromDiagonal(down, out);

		if (pickedVertexState != null) {
			if (clear) {
				pickedVertexState.clear();
			}
			GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();

			Collection<V> picked = pickSupport.getVertices(layout, pickRectangle);
			for (V v : picked) {
				pickedVertexState.pick(v, true);
			}
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// stub
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		JComponent c = (JComponent) e.getSource();
		c.setCursor(cursor);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		JComponent c = (JComponent) e.getSource();
		c.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		// stub
	}

	/**
	 * @return Returns the locked.
	 */
	public boolean isLocked() {
		return locked;
	}

	/**
	 * @param locked The locked to set.
	 */
	public void setLocked(boolean locked) {
		this.locked = locked;
	}
}
