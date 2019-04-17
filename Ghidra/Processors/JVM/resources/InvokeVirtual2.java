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
public class InvokeVirtual2{

    public long func2_2(long a){
        return a + 1;
    }
    
    public long func2_2_2(long a, long b){
        return a + b;
    }

    public long longTest2(long a, long b){
       long c = func2_2(a);
       long d = func2_2(b);
       long e = func2_2_2(c,d);
       return e + 1;
    }


}
