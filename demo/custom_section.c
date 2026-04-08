#include <stdio.h>

__attribute__((section(".my_custom_data")))
const char msg[] = "custom section";

int main()
{
  printf("Non-standard sections: %s\n", msg);
  return 0;
}
