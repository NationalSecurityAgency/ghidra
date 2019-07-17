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
class MultiANewArrayTests{

   public Integer twoMultiAnewArrayCalls(){
       Integer[][][][][][][][] one = new Integer[1][2][3][4][5][6][7][8];
       Integer[][][][][][][] two = new Integer[1][2][3][4][5][6][7];
       return one[1][2][3][4][5][6][7][8] + two[1][2][3][4][5][6][7];
    }
} 

