/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.utils.*;
import ghidra.sleigh.grammar.Location;


public abstract class PatternValue extends PatternExpression {
	
  public PatternValue(Location location) {
        super(location);
    }
public abstract TokenPattern genPattern(long val);
  @Override
public void listValues(VectorSTL<PatternValue> list) { 
	  list.push_back(this); 
  }
  
  @Override
public void getMinMax(VectorSTL<Long> minlist, VectorSTL<Long> maxlist)  { 
	  minlist.push_back(minValue()); 
	  maxlist.push_back(maxValue());
  }

  @Override
public long getSubValue( VectorSTL<Long> replace,MutableInt listpos)  {
	  long res = replace.get(listpos.get());
	  listpos.increment();
	  return res;
  }
  public abstract long minValue();
  public abstract long maxValue();
}
