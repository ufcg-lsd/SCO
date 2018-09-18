#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int sum(char* p_inputs)
{
    int a = ((int *) p_inputs)[0];
    int b = ((int *) p_inputs)[1];
    return a + b;
}

long long fibonacci(char* p_inputs)
{
    int n = ((int *) p_inputs)[0];
    long long prev = 0;
    long long curr = 1;
    long long next;

    if (n < 2)
        return n;

    int i;
    for (i = 1; i < n; i++) {
        next = prev + curr;
        prev = curr;
        curr = next;
    }
    return curr;
}

int check_password(char* p_inputs)
{
    char password[] = "topsecret1234";
    return !strcmp( p_inputs, password );
}

int main(){}