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
class BreakTest{

    public int break1(int x){
        for (int i = 0; i < 10; i++){
            if (x == i){
                break;
            }
            x++;
         }
         return x;
    }

    public int continue1(int x){
        for (int i = 0; i < 10; i++){
            if (x == i){
                continue;
            }
            x++;
         }
         return x;
    }

    public int break2(int x){
        for (int i = 0; i < 10; i++){
            for (int j = i; j < 10; j++){
                if (j == x){
                    break;
                }
                x++;
            }
         }
         return x;
    }

    public int continue2(int x){
        for (int i = 0; i < 10; i++){
            for (int j = i; j < 10; j++){
                if (j == x){
                    continue;
                }
                x++;
            }
         }
         return x;
    }

    public int break3(int x){
        for (int i = 0; i < 10; i++){
            x++;
            if (x == i){
                break;
            }
         }
         return x;
    }

    public int continue3(int x){
        for (int i = 0; i < 10; i++){
            x++;
            if (x == i){
                continue;
            }
         }
         return x;
    }

    public int break4(int x){
        for (int i = 0; i < 10; i++){
            x++;
            if (x == i){
                break;
            }
            x++;
         }
         return x;
    }

    public int continue4(int x){
        for (int i = 0; i < 10; i++){
            x++;
            if (x == i){
                continue;
            }
            x++;
         }
         return x;
    }
}
