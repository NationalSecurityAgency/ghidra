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
package ghidra.pcodeCPort.globalcontext;

public class ContextBitRange {

      private int word;
      private int startbit;
      private int endbit;
      private int shift;
      private int mask;

  public ContextBitRange() { // For use with restoreXml      
  } 
  
  public ContextBitRange(int sbit,int ebit) {
      word = sbit/(32);
      startbit = sbit - word*32;
      endbit = ebit - word*32;
      shift = 32-endbit-1;
      mask = -1 >>> (startbit+shift);
  }
  
  public void setValue(int[] vec, int val) {
    int newval = vec[word];
    newval &= ~(mask<<shift);
    newval |= ((val & mask)<<shift);
    vec[word] = newval;
  }
  
  public int getValue(int[] vec) {
    return ((vec[word]>>shift)&mask);
  }
}
