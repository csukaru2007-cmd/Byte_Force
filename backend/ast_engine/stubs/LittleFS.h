// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <FS.h>
class LittleFSFS : public fs::FS { public: bool begin(bool formatOnFail = false); };
extern LittleFSFS LittleFS;
