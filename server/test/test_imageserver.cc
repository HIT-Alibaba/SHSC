#include "image/image_server.cc"

#include <signal.h>


using namespace shsc;
using namespace std;

static bool stop = false;

void SignalStop(int) {
  LOG_TRACE("Stop running...");
  stop = true;
}

int main() {
  ::signal(SIGINT, SignalStop);

  log::SetLogLevel(log::TRACE);

  EventPool event_pool(1, 1);
  InetAddress bindaddr("0.0.0.0", 19910);
  event_pool.Run();
  ImageServer server(&event_pool, bindaddr);
  server.Start();

  while (true) {
    if (stop) {
      event_pool.Stop();
      break;
    }
    ::usleep(1000);
  }
}


