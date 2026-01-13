#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

int main(){

    struct timeval start, end;
    long mtime = 0, seconds, useconds;

    gettimeofday(&start, NULL);

    while (mtime < 2000){
        
        gettimeofday(&end, NULL);
        seconds  = end.tv_sec  - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;

    }
    

}