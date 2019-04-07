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
package functioncalls.plugin;

import com.google.common.cache.*;

import functioncalls.graph.FunctionCallGraph;
import ghidra.program.model.listing.Function;

/**
 * A factory that will create {@link FunctionCallGraph} data objects for a given function.  
 * Internally, this factory uses an MRU cache.	
 */
public class FcgDataFactory {

	private LoadingCache<Function, FcgData> cache;

	FcgDataFactory(RemovalListener<Function, FcgData> listener) {
		//@formatter:off
		cache = CacheBuilder
			.newBuilder()
		    .maximumSize(5)
		    .removalListener(listener)
			// Note: using soft values means that sometimes our data is reclaimed by the 
			//       Garbage Collector.  We don't want that, we wish to call dispose() on the data
		    //.softValues() 
		    .build(new CacheLoader<Function, FcgData>() {
		    	@Override
		    	public FcgData load(Function f) throws Exception {
		    		return new ValidFcgData(f, new FunctionCallGraph());
		    	}
		    });
		//@formatter:on 
	}

	FcgData create(Function f) {
		if (f == null) {
			return new EmptyFcgData();
		}

		FcgData data = cache.getUnchecked(f);
		return data;
	}

	void remove(Function f) {
		cache.invalidate(f);
	}

	void dispose() {
		cache.invalidateAll();
	}
}
