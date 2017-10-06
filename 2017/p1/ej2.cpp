#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
using namespace std;
int main()
{

	srand(time(NULL));   // should only be called once
	int r = rand()%40;      // 40 primeras posiciones
	cout<<"\nPosicion r "<<r<<endl;
    FILE* pFile;
    pFile = fopen("input1.bin", "wb");
    int buffer[1] = {0};
   int buffer2[1] = {1};
    for (int j = 0; j < 1024; ++j){
        if (j==r){
           fwrite(buffer2,sizeof(int),sizeof(buffer2),pFile);
	}
	else{
	   fwrite(buffer,sizeof(int),sizeof(buffer),pFile);
	}
    }
    fclose(pFile);
    return 0;
}

