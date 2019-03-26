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
package ghidra.util.graph;

import java.util.Iterator;
import java.util.Vector;

import ghidra.util.Msg;
import ghidra.util.exception.NoValueException;
import ghidra.util.graph.attributes.*;

/**
 * Title: Dominator
 * Description: This class contains the functions necessary to build the
 * dominance graph of a FlowGraph, ShrinkWrap or Modularized Graph.
 * A more complete explanation of my algorithm can be found in my paper
 * titled "Building a Dominance Graph"
 *
 */

public class Dominator extends DirectedGraph //implements Weighted
{
	private IntegerAttribute<Vertex> vertexColor;
	private ObjectAttribute<Vertex> callingParent;
	private DoubleAttribute<Vertex> vertexWeight;
	private DoubleAttribute<Edge> edgeWeight;
	private StringAttribute<Vertex> vertexType;
	private Path paths;

	private static final int white = 0;
	private static final int gray = 1;

	//Constructors
	public Dominator(int vertexCapacity, int edgeCapacity) {
		super(vertexCapacity, edgeCapacity);
		paths = new Path();
		vertexColor =
			(IntegerAttribute<Vertex>) vertexAttributes().createAttribute("Color",
				AttributeManager.INTEGER_TYPE);
		callingParent =
			(ObjectAttribute<Vertex>) vertexAttributes().createAttribute("Calling Parent",
				AttributeManager.OBJECT_TYPE);
		vertexWeight =
			(DoubleAttribute<Vertex>) vertexAttributes().createAttribute("Weight",
				AttributeManager.DOUBLE_TYPE);
		edgeWeight =
			(DoubleAttribute<Edge>) edgeAttributes().createAttribute("Weight",
				AttributeManager.DOUBLE_TYPE);
		vertexType =
			(StringAttribute<Vertex>) vertexAttributes().createAttribute("Type",
				AttributeManager.STRING_TYPE);
	}

	public Dominator() {
		this(101, 101);
	}

	public Dominator(DirectedGraph cg) {
		this();
		GraphIterator<Vertex> vertexIter = cg.vertexIterator();

		while (vertexIter.hasNext()) {
			Vertex next = vertexIter.next();
			this.add(next);
			//this.setWeight(next, cg.getWeight(next));
			this.setColor(next, white);
		}

		GraphIterator<Edge> edgeIter = cg.edgeIterator();

		while (edgeIter.hasNext()) {
			Edge next = edgeIter.next();
			if (!(next.to().equals(next.from()))) {
				this.add(next);
				//this.setWeight(next, cg.getWeight(next));
			}
		}

	}

	/* public Dominator(ShrinkWrap sw)
	 {
	   this();
	   KeyIndexableSet.Iterator it = sw.vertexIterator();

	   while(it.hasNext())
	   {
	     Vertex next = (Vertex)it.next();
	     this.add(next);
	     this.setWeight(next, sw.getWeight(next));
	     this.setColor(next,white);
	     this.setType(next, sw.getType(next));
	   }

	   it = sw.edgeIterator();
	   while(it.hasNext())
	   {
	     Edge next = (Edge)it.next();
	     if(!(next.to().equals(next.from()))){
	       this.add(next);
	       this.setWeight(next, sw.getWeight(next));
	     }
	   }
	 }
	*/
	/**
	 * this aids in going back to the parent from which a vertex was accessed in
	 * the depth first search
	 */

	public Vertex backTrack(Vertex v) {
		return this.getCallingParent(v);
	}

	/**
	 * this returns the vertex that is the dominator
	 */
	public Vertex getDominator(Vertex v) {
		Vector pathSet = this.allPathsContaining(v);
		if (pathSet.isEmpty()) {
			return v;
		}
		Vector path = (Vector) pathSet.firstElement();
		return this.allPathsContain(pathSet, v, path);
	}

	/**
	 * this returns all paths that contain v which we need to consider when
	 * looking for the dominator of v.  It places the longest path as the
	 * first element in the vector pathSet.
	 */
	public Vector allPathsContaining(Vertex v) {
		int i, maxsize = 0;
		Vector pathSet = new Vector();
		for (i = 0; i < paths.size(); i++) {
			Vector tmpPath = (Vector) paths.elementAt(i);
			if (tmpPath.contains(v)) {
				if (tmpPath.size() > maxsize) {
					maxsize = tmpPath.size();
					pathSet.add(0, tmpPath);
				}
				else {
					pathSet.add(paths.elementAt(i));
				}
			}
		}
		return pathSet;
	}

	/**
	 * This takes the longest path that contains vertex v and looks to see
	 * if any of v's ancestors from that path are contained in all other
	 * paths that contain v.
	 */
	public Vertex allPathsContain(Vector pathSet, Vertex v, Vector path) {
		int candIndex = path.indexOf(v) - 1;
		if (!(candIndex >= 0)) {
			return v;
		}
		Vertex candidate = (Vertex) path.elementAt(candIndex--);
		int i;
		boolean flag = false;
		while (!flag) {
			flag = true;
			for (i = 0; i < pathSet.size(); i++) {
				if (!((Vector) pathSet.elementAt(i)).contains(candidate)) {
					flag = false;
				}
			}
			if (!flag) {
				candidate = (Vertex) path.elementAt(candIndex--);
			}
		}
		return candidate;

	}

	/**
	 * Goes to the next child of v that has not been visited and sets the
	 * calling parent to be v so that we can backtrack.
	 */
	public Vertex goToNextWhiteChild(Vertex v) {
		if (this.hasWhiteChild(v)) {
			Iterator<Vertex> it = this.getChildren(v).iterator();
			while (it.hasNext()) {
				Vertex nextChild = it.next();
				if (this.getColor(nextChild) == white) {
					this.setCallingParent(nextChild, v);
					return nextChild;
				}
			}
		}
		return null;
	}

	/**
	 * This makes a list of all the paths that are in a graph that terminate
	 * either because of a repeated vertex or hitting a sink. It then calls
	 * getDominanceGraph which gets the dominator for every vertex and builds a
	 * dominance graph.
	 */
	public DirectedGraph setDominance() {
		Vertex[] roots = this.getSources();
		int i = 0;

		/* Check to make sure we have only one root.  In setting the dominance
		 on a graph with more than one component, use the function
		 setDominanceForModularGraph which checks to see if each components
		 contains only one root.  Setting dominance for that type of graph takes
		 longer.
		*/

		if (roots.length != 1) {

			if (roots.length > 1) {
				Msg.error(this, "this should not print because it means you have more than 1 root");
			}
			else if (roots.length == 0) {
				Msg.error(this, "You need a root,no root provided");
			}
			else {
				Msg.error(this, "Your number of roots is " + roots.length);
			}

			return null;

		}
		Vertex v = roots[0];
		Vector singlePath = new Vector();
		// set the dominance on a graph
		while (this.hasWhiteChild(v) || !v.equals(roots[0])) {
			v = this.addToPaths(v, singlePath);
			if (!(paths.containsInSomeElement(singlePath))) {
				int j;
				paths.add(i, singlePath);
				singlePath = new Vector();
				for (j = 0; j < ((Vector) paths.elementAt(i)).size(); j++) {
					singlePath.add(j, ((Vector) paths.elementAt(i)).elementAt(j));
				}
				i++;
			}
			this.whitenChildren(v);
			v = this.backTrack(v);
			singlePath.removeElementAt(singlePath.size() - 1);
		}
		return this.getDominanceGraph();
	}

	/**
	 * This iterates through the vertices of our graph and gets the dominator
	 * for each.  In a new graph - dom - it adds each vertex and an edge between the
	 * vertex and its dominator.  It returns dom, the dominance graph.
	 */
	public DirectedGraph getDominanceGraph() {
		DirectedGraph dom = new Dominator();
		GraphIterator<Vertex> it = this.vertexIterator();

		if (this.numVertices() == 1) {

			dom.add(this.getSources()[0]);
			return dom;
		}

		while (it.hasNext()) {
			Vertex next = it.next();
			if (!(this.getSources()[0].equals(next))) {
				Vertex parent = this.getDominator(next);
				dom.add(next);
				dom.add(parent);
				dom.add(new Edge(parent, next));
			}
		}
		return dom;
	}

	/**
	 * This function originally did not return anything.  It returns a vertex
	 * for the purpose of keeping track of which vertex we left off on.  So if we
	 * backtrack, we can copy the portion of the previous path that is contained
	 * in the path we are currently construction.  I tried to do this without
	 * passing v as a parameter and it did not work.  Something funny happened I
	 * suppose with JAVA and pointers.
	 * This  function simply adds to singlePath until there are no more white
	 * children which means we've either reached a sink, or the only vertices
	 * left are repeated meaning we have a loop.
	 */
	public Vertex addToPaths(Vertex v, Vector singlePath) {
		int i = singlePath.size();
		this.setColor(v, gray);
		if (!singlePath.contains(v)) {
			singlePath.add(i++, v);
		}
		while (this.hasWhiteChild(v)) {
			v = this.goToNextWhiteChild(v);
			this.setColor(v, gray);
			singlePath.add(i++, v);
		}

		return v;
	}

	// checks to see if there are any children of v not yet visited
	private boolean hasWhiteChild(Vertex v) {
		boolean flag = false;
		Iterator<Vertex> it = this.getChildren(v).iterator();
		while (it.hasNext()) {
			Vertex nextChild = it.next();
			if (this.getColor(nextChild) == white) {
				flag = true;
			}
		}
		return flag;
	}

	/**
	 *  Whitens the children of v.  It is only called after v has no more
	 *  children left and we have backtracked to the calling parent of
	 *  v.  This is to ensure that we don't miss out on any paths that
	 *  contain a child of v which has other parents.
	 */
	public void whitenChildren(Vertex v) {
		Iterator<Vertex> it = this.getChildren(v).iterator();
		while (it.hasNext()) {
			Vertex next = it.next();
			if (this.getCallingParent(next).equals(v)) {
				this.setColor(next, white);
			}
		}
	}

	// sets the color of a vertex
	public void setColor(Vertex v, int color) {
		if (this.contains(v)) {
			vertexColor.setValue(v, color);
		}
	}

	// gets the color of a vertex
	public int getColor(Vertex v) {
		try {
			return vertexColor.getValue(v);
		}
		catch (NoValueException exc) {
			return white;
		}
	}

	// sets the calling parent of a vertex
	public void setCallingParent(Vertex v, Vertex parent) {
		if (this.contains(v)) {
			callingParent.setValue(v, parent);
		}
	}

	// gets the calling parent of a vertex
	public Vertex getCallingParent(Vertex v) {
		return (Vertex) callingParent.getValue(v);
	}

	// sets the type of vertex
	public void setType(Vertex v, String type) {
		if (this.contains(v)) {

			//try
			//{
			vertexType.setValue(v, type);
			/*}
			catch( NoValueException exc )
			{
			}*/
		}
	}

	// gets the type of a vertex
	public String getType(KeyedObject o) {
		String type = null;

		type = vertexType.getValue(o);

		return type;
	}

	// sets the weight of a vertex
	public void setWeight(Vertex v, double weight) {
		if (this.contains(v)) {
			vertexWeight.setValue(v, weight);
		}
	}

	// gets the weight of a vertex
	public double getWeight(Vertex v) {
		try {
			return vertexWeight.getValue(v);
		}
		catch (NoValueException exc) {
			return 0.0;
		}
	}

	// sets the weight of an edge
	public void setWeight(Edge e, double weight) {
		if (this.contains(e)) {
			edgeWeight.setValue(e, weight);
		}
	}

	// gets the weight of an edge
	public double getWeight(Edge e) {
		try {
			return edgeWeight.getValue(e);
		}
		catch (NoValueException exc) {
			return 0.0;
		}
	}

}
