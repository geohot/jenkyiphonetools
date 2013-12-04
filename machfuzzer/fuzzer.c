#include <stdarg.h>
#include <IOSurface/IOSurface.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdint.h>

void hexdump(unsigned char* dat, int l) {
  int i;
  for (i = 0; i < l; i++) {
    if (i!=0&&i%0x10==0) printf("\n");
    printf("%2.2x ", dat[i]);
  }
  printf("\n");
}

/* ADD FUZZIES HERE */

io_connect_t open_service(char *service_name) {
  CFMutableDictionaryRef matchingDict;
  kern_return_t kernResult; 
  mach_port_t masterPort;
  io_iterator_t iter;
  io_service_t service;
  io_connect_t connect;

  kernResult = IOMasterPort(MACH_PORT_NULL, &masterPort);
  if (kernResult != KERN_SUCCESS) printf("IOMasterPort failed\n");
  matchingDict = IOServiceMatching(service_name);
  if (matchingDict == NULL) printf("matchingDict is NULL\n");
  kernResult = IOServiceGetMatchingServices(masterPort, matchingDict, &iter);
  if (kernResult != KERN_SUCCESS) printf("IOServiceGetMatchingServices failed\n");
  service = IOIteratorNext(iter);
  kernResult = IOServiceOpen(service, mach_task_self(), 1, &connect);
  if (kernResult != KERN_SUCCESS) {
    printf("IOServiceOpen failed %s\n", service_name);
    return -1;
  } else {
    printf("opened %s\n", service_name);
  }
  return connect;
}


int main(int argc, char* argv[]) {
  int i;
  printf("fuzzing %s\n", SERVICENAME);
  kern_return_t kernResult; 
  io_connect_t connect;


  int seed = time(NULL);
  printf("seed is %d\n", seed);
  srand(seed);

  connect = open_service(SERVICENAME);

  unsigned char in[0x2000];
  unsigned char out[0x2000];
  uint64_t inc[100];
  uint64_t outc[100];
  size_t out_size;
  uint32_t outc_size;
  while(1) {
    memset(in, 0, 0x2000);
    memset(inc, 0, 100*sizeof(uint64_t));

    int method = rand() % (sizeof(ii)/sizeof(int));

    if (method == 5) continue;
    //if (method == 7) continue;
    //if (method == 1) continue;

    for (i = 0; i < ii[method]; i++) in[i] = rand() % 0xF;
    for (i = 0; i < iic[method]; i++) inc[i] = (rand() << 16) + rand();

    printf("running %d -- %d %d %d %d\n", method, in[0], in[1], in[2], in[3]);

    out_size = oo[method];
    outc_size = ooc[method];
    //kernResult = IOConnectCallStructMethod(connect, method, in, ii[method], out, &out_size);
    kernResult = IOConnectCallMethod(connect, method, inc, iic[method], in, ii[method], outc, &outc_size, out, &out_size);
    if (kernResult != KERN_SUCCESS) printf("IOConnectCallMethod failed %X\n", kernResult);
    
    printf("ran %d got %X %zX\n", method, kernResult, out_size);
    if (kernResult == KERN_SUCCESS) {
      hexdump(out, out_size);
    }
  }

  return 0;
}

