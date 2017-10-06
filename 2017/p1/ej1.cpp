#include <stdio.h>

int main()
{
    FILE* pFile;
    pFile = fopen("input.bin", "wb");
    int buffer[1] = {0};
    for (int j = 0; j < 1024; ++j){
        //Some calculations to fill a[]
        fwrite(buffer,sizeof(int),sizeof(buffer),pFile);;
    }
    fclose(pFile);
    return 0;
}
