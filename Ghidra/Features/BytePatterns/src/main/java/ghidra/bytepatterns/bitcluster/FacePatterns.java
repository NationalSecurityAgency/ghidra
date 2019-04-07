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
package ghidra.bytepatterns.bitcluster;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

public class FacePatterns {

	private int maxDim;					// Maximum number of dits to have to be accepted as a pattern. 
	private HashSet<Face> patterns;		// Patterns of ditted bit sequences (faces).
	private int sampleSize;				// Maximum number of sequences to try and cluster at once

	//Constructor: runs agglomerative clustering on ditted bit sequences.
	public FacePatterns(int sampsize) {
		patterns = null;
		sampleSize = sampsize;
	}

	//Returns the patterns currently stored.
	public HashSet<Face> generatePatterns(ArrayList<byte[]> bytes, int minBitsOfCheck) {
		if (bytes.isEmpty()) {
			return null;
		}
		ArrayList<byte[]> forSample = sample(bytes, sampleSize);
		this.patterns = new HashSet<Face>();
		int numBytes = forSample.get(0).length;
		this.maxDim = numBytes * 8 - minBitsOfCheck;
		this.createFaces(forSample);					//Transform the bytes into ditted bit sequences. Changes this.patterns.
		TreeSet<Face> edges = this.createEdges();		//Initialize the n choose 2 cluster distances.
		this.cluster(edges);							//Agglomerates patterns by picking optimal edges.
		return this.patterns;
	}

	//Creates a list of ditted bit sequences to cluster.
	private void createFaces(ArrayList<byte[]> sequences) {
		//Creates an entry in the list for each function in the current program.
		HashMap<String, Face> faceByName = new HashMap<String, Face>();	//Dictionary arranged by face name.

		for (byte[] seq : sequences) {
			Face node = new Face(seq);
			String name = node.strID;
			if (faceByName.containsKey(name)) {
				faceByName.get(name).incrementWeight();					//If we've seen this sequence before, add to its weight.
			}
			else {
				faceByName.put(name, node);								//Don't worry...the weight starts at 1.
				this.patterns.add(node);								//This face represents a yet unseen pattern.
			}
		}
		return;
	}

	//Set up the initial n choose 2 clusters consisting of the n dimension 0 data points (but with weight).
	private TreeSet<Face> createEdges() {
		Face[] faceList = this.patterns.toArray(new Face[this.patterns.size()]);
		TreeSet<Face> edgesConsidered = new TreeSet<Face>();			//Ordered list of joins to agglomerate.
		for (int indexA = 0; indexA < faceList.length - 1; indexA++) {
			Face f1 = faceList[indexA];
			for (int indexB = indexA + 1; indexB < faceList.length; indexB++) {
				Face f2 = faceList[indexB];
				//Propose a new edge with hypothetical children.
				Face edge = new Face(f1, f2, this.patterns, maxDim, false);
				if (edge.getNumUncertainBits() <= this.maxDim) {						//Too many dits to be a good pattern.
					edgesConsidered.add(edge);
				}
			}
		}
		return edgesConsidered;
	}

	//Performs the agglomerative clustering. edgesConsidered is maintained as a set of potential next pairs of clusters to join.
	private void cluster(TreeSet<Face> edgesConsidered) {
		HashMap<String, Face> added = new HashMap<String, Face>();		//For keeping track of clusters clustered.
		//Among the edges considered, choose the best one and combine clusters. Or eliminate useless edges.
		while (edgesConsidered.size() > 0) {
			Face bestEdge = edgesConsidered.last();
			//Check to make sure this is a good edge to add (not already included, etc.).
			if (bestEdge.meetsCriteria(this.patterns, added)) {
				this.patterns.removeAll(bestEdge.getChildren());		//Lower level, old patterns removed.
				for (Face outside : this.patterns) {
					Face edge = new Face(bestEdge, outside, this.patterns, maxDim, true);
					if (edge.getNumUncertainBits() <= this.maxDim) {					//Patterns are bad without enough bits of check.
						edgesConsidered.add(edge);
					}
				}
				this.patterns.add(bestEdge);							//We've added a high level, new pattern.
				added.put(bestEdge.strID, bestEdge);
			}
			edgesConsidered.remove(bestEdge);							//Done with this pair of clusters.
		}
		return;
	}
	
	//Recursively creates the edge list under a node in a DAG.
	static private HashSet<String> edgize(Face node) {
		HashSet<String> result = new HashSet<String>();
		for (Face kid : node.getChildren()) {
			result.add(node.strID + "," + kid.strID);			//"vertex1,vertex2" a directed edge
			result.addAll(edgize(kid));					//Recursion works given a DAG.
		}
		return result;
	}

	//Sends the hierarchy (as a graph edge list) to a file.
	public void outputHierarchy(Writer writer) throws IOException {
		HashSet<String> edgeStrs = new HashSet<String>();
		for (Face f : patterns) {
			edgeStrs.addAll(edgize(f));
		}

		for (String line : edgeStrs) {
			writer.write(line + "\n");
		}
	}
	
	//Sends a list of faces to a file (as a list of ditted bit sequences).
	public void outputTopPatterns(Writer writer) throws IOException {
		for (Face f : patterns) {
			writer.write(f.strID + '\t' + f.getWeight() + '\t' + ((Double) f.ratioFilled()).toString() + "\n");
		}
	}

	//Samples a list of byte sequences.
	static private ArrayList<byte[]> sample(ArrayList<byte[]> li, int numOfSamples) {
		ArrayList<byte[]> result = new ArrayList<byte[]>();
		Random rand = new Random();
		for (int s = 0; s < numOfSamples; s++) {
			int r = rand.nextInt(li.size());
			result.add(li.get(r));
		}
		return result;
	}
}
