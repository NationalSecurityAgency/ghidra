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
package ghidra.features.bsim.query;

import generic.lsh.vector.LSHVector;
import ghidra.features.bsim.gui.search.results.BSimMatchResult;

public class ChildMatchRecord implements Comparable<ChildMatchRecord>{

		BSimMatchResult similarFunction;
		LSHVector vecWithChildren;
		double significanceWithChildren;
		double similarityWithChildren;


		public ChildMatchRecord(BSimMatchResult match, LSHVector vec){
			this.similarFunction = match;
			this.vecWithChildren = vec;
		}

		public BSimMatchResult getSimilarFunction(){
			return this.similarFunction;
		}

		public LSHVector getVecWithChildren(){
			return this.vecWithChildren;
		}

		public void setSignificanceWithChildren(double newSignif){
			this.significanceWithChildren = newSignif;
		}

		public double getSignificanceWithChildren(){
			return this.significanceWithChildren;
		}

		public void setSimilarityWithChildren(double newSim){
			this.similarityWithChildren = newSim;
		}

		public double getSimilarityWithChildren(){
			return this.similarityWithChildren;
		}

		@Override
		public int compareTo(ChildMatchRecord arg0) {
			return Double.compare(arg0.getSignificanceWithChildren(), this.significanceWithChildren);
		}

	}
