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
package ghidra.trace.model.symbol;

import ghidra.trace.model.Lifespan;

/**
 * A trace symbol having a lifespan.
 */
public interface TraceSymbolWithLifespan extends TraceSymbol {
	/**
	 * Get the lifespan of the symbol
	 * 
	 * @return the lifespan
	 */
	Lifespan getLifespan();

	/**
	 * Get the minimum snapshot key in the lifespan
	 * 
	 * @return the minimum snapshot key
	 */
	long getStartSnap();

	/**
	 * Set the maximum snapshot key in the lifespan
	 * 
	 * @param snap the new maximum snapshot key
	 */
	void setEndSnap(long snap);

	/**
	 * Get the maximum snapshot key in the lifespan
	 * 
	 * @return the maximum snapshot key
	 */
	long getEndSnap();
}
